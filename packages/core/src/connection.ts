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

import axios, { AxiosRequestConfig } from "axios";
import { IBaseTransaction, IConnectionDataOptions, IHttpOptions, ILedgerResponse } from "./interfaces";

/**
 * Handles connecting to the ledger and sending transactions. Axios is
 * isomorphic (XHR in browsers/React Native, http in Node) so this class
 * needs no platform-specific code and lives entirely in core.
 *
 * @export
 * @class Connection
 */
export class Connection {
  private options: IConnectionDataOptions;
  private httpOptions: IHttpOptions;

  /**
   * Creates an instance of Connection.
   * @param {IConnectionDataOptions} options
   * @memberof Connection
   */
  constructor(options: IConnectionDataOptions);
  /**
   * Creates an instance of Connection.
   * @param {string} protocol - The protocol to use, usually http or https
   * @param {string} address - The URL or IP of the node
   * @param {number} portNumber - The port number of the node
   * @memberof Connection
   */
  constructor(protocol: string, address: string, portNumber: number | string);
  constructor(optionsOrProtocol: string | IConnectionDataOptions, address?: string, portNumber?: number | string) {
    const generateOptions = (): IConnectionDataOptions => {
      return {
        address: address as string,
        portNumber: portNumber as number | string,
        protocol: optionsOrProtocol as string,
      };
    };

    this.options = typeof optionsOrProtocol === "string" ? generateOptions() : optionsOrProtocol;

    this.httpOptions = {
      baseURL: this.options.protocol + "://" + this.options.address + ":" + this.options.portNumber,
      headers: { "Content-Type": "application/json" },
      method: "POST",
      port: this.options.portNumber,
    };
  }

  /**
   * Send a transaction to the specified ledger
   *
   * @param {IBaseTransaction} txBody - The Body of the transaction
   * @returns {Promise<ILedgerResponse>} Returns the ledger response
   * @memberof Connection
   */
  public sendTransaction(txBody: IBaseTransaction): Promise<ILedgerResponse> {
    return new Promise(async (resolve, reject) => {
      try {
        const response = await this.postTransaction(txBody);
        resolve(response);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * POST the provided transaction to the ledger
   *
   * @private
   * @param {IBaseTransaction} tx - The transaction to POST
   * @returns {Promise<ILedgerResponse>} Returns the ledger response
   * @memberof Connection
   */
  private postTransaction(tx: IBaseTransaction): Promise<ILedgerResponse> {
    return new Promise(async (resolve, reject) => {
      this.httpOptions.data = tx;

      try {
        const response = await axios(this.httpOptions as AxiosRequestConfig);
        resolve(response.data as ILedgerResponse);
      } catch (error) {
        reject(error);
      }
    });
  }
}
