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

import * as fs from "fs";
import { IKey, KeyHandler as CoreKeyHandler } from "@activeledger/sdk-core";
import { IKeyExportOptions } from "./interfaces";
import { NodeCryptoProvider } from "./crypto";

/**
 * Adds file-based key import/export to the core KeyHandler - "a file" is a
 * Node-only concept, so it lives here rather than in sdk-core.
 *
 * @export
 * @class KeyHandler
 */
export class KeyHandler extends CoreKeyHandler {
  constructor() {
    super(new NodeCryptoProvider());
  }

  /**
   * Export a key to a file
   *
   * @param {IKey} key - The key to export
   * @param {IKeyExportOptions} options - The configuration options for the export
   * @returns {Promise<void>}
   * @memberof KeyHandler
   */
  public exportKey(key: IKey, options: IKeyExportOptions): Promise<void>;
  /**
   *
   *
   * @param {IKey} key
   * @param {string} location - The location to save the key to
   * @param {boolean} [createDir] - (Optional) Create the directory structure
   * @param {boolean} [overwrite] - (Optional) Overwrite an existing file if it exists
   * @param {string} [name] - (Optional) - Set a name for the file
   * @returns {Promise<void>}
   * @memberof KeyHandler
   */
  public exportKey(
    key: IKey,
    location: string,
    createDir?: boolean,
    overwrite?: boolean,
    name?: string,
  ): Promise<void>;
  public exportKey(
    key: IKey,
    locationOrOptions: string | IKeyExportOptions,
    createDir?: boolean,
    overwrite?: boolean,
    name?: string,
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      const setOptions = (): IKeyExportOptions => {
        return {
          createDir: createDir ? true : false,
          location: locationOrOptions as string,
          name,
          overwrite: overwrite ? true : false,
        };
      };

      const options: IKeyExportOptions =
        typeof locationOrOptions === "string" ? setOptions() : (locationOrOptions as IKeyExportOptions);

      // Recursively create dir
      if (options.createDir) {
        try {
          fs.mkdirSync(options.location, { recursive: true });
        } catch (err) {
          return reject(err);
        }
      }

      // Strip trailing /
      options.location = this.stripTrailing(options.location);

      // Set name of file
      const path = options.name ? `${options.location}/${options.name}.json` : `${options.location}/${key.name}.json`;

      // Check folder exists
      const dirExists = fs.existsSync(options.location);
      if (dirExists) {
        // Check if the file exists
        const fileExists = fs.existsSync(path);
        // If exists and overwrite is false
        if (fileExists && !options.overwrite) {
          reject("File already exists, set overwrite to true or use a different name");
        } else {
          // Write
          fs.writeFile(path, JSON.stringify(key), (error: NodeJS.ErrnoException | null) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          });
        }
      } else {
        reject("Unable to find location");
      }
    });
  }

  /**
   * Import a key from a file
   *
   * @param {string} path - The location of the key file
   * @returns {Promise<IKey>}
   * @memberof KeyHandler
   */
  public importKey(path: string): Promise<IKey> {
    return new Promise((resolve, reject) => {
      fs.exists(path, (fileExists: boolean) => {
        if (fileExists) {
          fs.readFile(path, (error: NodeJS.ErrnoException | null, buffer: Buffer) => {
            if (error) {
              reject(error);
            } else {
              const data = buffer.toString();
              resolve(JSON.parse(data) as IKey);
            }
          });
        } else {
          reject("File not found.");
        }
      });
    });
  }

  /**
   * Remove a trailing / from the location
   *
   * @private
   * @param {string} path - String to strip from
   * @returns {string}
   * @memberof KeyHandler
   */
  private stripTrailing(path: string): string {
    const lastChar = path.slice(path.length - 1, path.length);
    if (lastChar === "/") {
      return path.slice(0, path.length - 1);
    }
    return path;
  }
}
