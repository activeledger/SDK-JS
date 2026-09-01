/*
 * MIT License (MIT)
 * Copyright (c) 2019 Activeledger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { EventEmitter } from "events";
import { EventSourceFactory, IEventConfig, IEventListeners } from "./interfaces";

/**
 * This class is used for easy access to the events API provided by the ActiveCore server.
 *
 * Takes an EventSourceFactory rather than importing an EventSource
 * implementation directly - the node package supplies one backed by the
 * `eventsource` npm package, the web package supplies one backed by the
 * environment's native `EventSource` global (available in every browser;
 * React Native apps need to polyfill it, same as WebCrypto).
 *
 * @export
 * @class LedgerEvents
 */
export class LedgerEvents {
  public errorEvents: EventEmitter;

  /**
   * Holds referenced listeners
   *
   * @private
   * @type {IEventListeners}
   * @memberof LedgerEvents
   */
  private listeners: IEventListeners = {};

  /**
   * Incremental reference identifier for listeners
   *
   * @private
   * @memberof LedgerEvents
   */
  private reference = 1;

  /**
   * Creates an instance of LedgerEvents.
   * @param {string} url - The ActiveCore URL
   * @param {EventSourceFactory} createEventSource - Platform-supplied EventSource constructor
   * @memberof LedgerEvents
   */
  constructor(private url: string, private createEventSource: EventSourceFactory) {
    // Check that the url has the correct protocol
    if (!(this.url.startsWith("http") || this.url.startsWith("https"))) {
      throw new Error("Activecore URL must include http:// or https://");
    }

    // We add the / so remove if found
    if (this.url.endsWith("/")) {
      this.url = this.url.substring(0, this.url.lastIndexOf("/") - 1);
    }

    // Is api part of the path
    if (!this.url.endsWith("api")) {
      this.url += "/api";
    }

    this.errorEvents = new EventEmitter();
  }

  /**
   * Subscribe to all Activity events
   *
   * /activity/subscribe - Recieve notifications for all activities on the ledger network.
   *
   * @param {Function} callback
   * @memberof LedgerEvents
   */
  public subscribeToActivity(callback: Function): number;
  /**
   * Subscribe to Activity events triggered by a specific stream
   *
   * activity/subscribe/{streamId} - Recieve notifications for this specific stream
   *
   * @param {string} streamId
   * @param {Function} callback
   * @returns {number}
   * @memberof LedgerEvents
   */
  public subscribeToActivity(streamId: string, callback: Function): number;
  public subscribeToActivity(streamIdOrCallback: string | Function, callback?: Function): number {
    // Keep a copy because we need to use it to store the event source and we need to return it to the caller
    const internalReference = this.reference;
    this.reference++;

    let streamId = null;

    typeof streamIdOrCallback === "string" ? (streamId = streamIdOrCallback) : (callback = streamIdOrCallback);
    if (!callback) throw new Error("No Callback defined");

    // Build the resource part of the URL
    const resource = streamId ? `activity/subscribe/${streamId}` : "activity/subscribe";

    const eventSource = this.createEventSource(`${this.url}/${resource}`);

    eventSource.onerror = (error: any) => {
      this.errorEvents.emit("ledgerEventError", error);
    };

    eventSource.addEventListener("message", (event: any) => {
      const data = JSON.parse(event.data);

      callback!(data.stream);
    });

    this.listeners[internalReference] = eventSource;
    return internalReference;
  }

  /**
   * Subscribe to contract specific events
   *
   * 1. /events - Subscribe to all contract events sent on the ledger
   * 2. /events/{config.contract} - Subscribe to events emitted by this contract only
   * 3. /events/{config.contract}/{config.event} - Subscribe to a specific event in a specific contract
   *
   * @param {Function} callback
   * @param {IEventConfig} config
   * @memberof LedgerEvents
   */
  public subscribeToEvent(callback: Function, config?: IEventConfig): number {
    // Keep a copy because we need to use it to store the event source and we need to return it to the caller
    const internalReference = this.reference;
    this.reference++;

    // Build the resource part of the URL
    let resource = "events";

    if (config) {
      // Event cannot be used without a contract reference
      if (config.event && !config.contract) throw new Error("Must pass contract to use event");
      if (config.contract) resource += `/${config.contract}`;
      if (config.event) resource += `/${config.event}`;
    }

    const eventSource = this.createEventSource(`${this.url}/${resource}`);

    eventSource.onerror = (error: any) => {
      this.errorEvents.emit("ledgerEventError", error);
    };

    eventSource.addEventListener("message", (event: any) => {
      const data = JSON.parse(event.data);

      callback!(data.event.data);
    });

    this.listeners[internalReference] = eventSource;
    return internalReference;
  }

  /**
   * Close a connection and remove it from the listeners
   *
   * @param {number} id
   * @returns {boolean}
   * @memberof LedgerEvents
   */
  public unsubscribe(id: number): boolean {
    // If anything at all goes wrong just return false
    try {
      // Remove the listener from the listeners array
      const eventSource = this.listeners[id];
      // Close the event connection
      eventSource.close();
      // Delete Reference
      delete this.listeners[id];
      return true;
    } catch (error) {
      return false;
    }
  }
}
