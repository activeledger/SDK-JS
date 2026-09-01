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

import { LedgerEvents as CoreLedgerEvents } from "@activeledger/sdk-core";

/**
 * Pre-wired with the environment's native `EventSource` global - every
 * browser has one. React Native does not ship one by default and needs a
 * polyfill (e.g. react-native-sse) registered as a global before use, the
 * same way it needs one for WebCrypto - this package deliberately doesn't
 * bundle a polyfill itself so plain web usage stays dependency-free.
 *
 * @export
 * @class LedgerEvents
 */
export class LedgerEvents extends CoreLedgerEvents {
  constructor(url: string) {
    super(url, (u: string) => new EventSource(u) as any);
  }
}
