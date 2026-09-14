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

import { Connection } from "./connection";
import { KeyType } from "./enums";
import { ICryptoProvider, IKey, ILedgerResponse } from "./interfaces";
import { TransactionHandler } from "./transaction";

/**
 * Handles generating and onboarding keys. File-based import/export lives in
 * each platform package instead, since "a file" isn't a universal concept
 * (Node has fs, browsers/React Native don't).
 *
 * @export
 * @class KeyHandler
 */
export class KeyHandler {
  constructor(private crypto: ICryptoProvider) {}

  /**
   * Generate a new key
   *
   * @param {string} keyName - The name of the key
   * @param {boolean} [compressed] - Return a compressed public key
   * @returns {Promise<IKey>} Returns the Key Object
   * @memberof KeyHandler
   */
  public generateKey(
    keyName: string,
    compressed?: boolean,
    type: KeyType = KeyType.EllipticCurve
  ): Promise<IKey> {
    return new Promise((resolve, reject) => {
      try {
        const keyHolder: IKey = {
          // `type` is third rather than second so existing positional calls
          // - generateKey(name, true) - keep meaning what they did. `compressed`
          // is a secp256k1 concept and is ignored by the post-quantum schemes.
          key: this.crypto.generate(compressed, type),
          name: keyName,
          type,
        };

        return resolve(keyHolder);
      } catch (error) {
        return reject(error);
      }
    });
  }

  /**
   * Onboard a key to the ledger and assign an identity to the key
   *
   * @param {IKey} key - The key to onboard
   * @param {Connection} connection - The connection to send the transaction over
   * @returns {Promise<ILedgerResponse>} Returns Ledger response as a promise
   * @memberof KeyHandler
   */
  public onboardKey(key: IKey, connection: Connection): Promise<ILedgerResponse> {
    return new Promise(async (resolve, reject) => {
      const txHandler = new TransactionHandler(this.crypto);

      try {
        const txBody = await txHandler.buildOnboardKeyTx(key);
        const response = await txHandler.sendTransaction(txBody, connection);
        key.identity = response.$streams.new[0].id;
        resolve(response);
      } catch (error) {
        reject(error);
      }
    });
  }
}
