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

import { KeyHandler as CoreKeyHandler } from "@activeledger/sdk-core";
import { WebCryptoProvider } from "./crypto.js";

/**
 * There's no file-based export/import here (unlike sdk-node) - "a file"
 * isn't a universal concept in browsers/React Native (localStorage,
 * AsyncStorage, SecureStore, IndexedDB... all differ per environment and
 * per app's own security requirements), so persisting the IKey object
 * `generateKey()` returns is left to the consuming application.
 *
 * @export
 * @class KeyHandler
 */
export class KeyHandler extends CoreKeyHandler {
  constructor() {
    super(new WebCryptoProvider());
  }
}
