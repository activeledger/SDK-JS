/*
 * MIT License (MIT)
 * Copyright (c) 2026 Activeledger
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

import { PayloadHandler as CorePayloadHandler } from "@activeledger/sdk-core";
import { NodeCryptoProvider } from "./crypto";

/**
 * Signs and verifies arbitrary payloads. Same name and same shape in
 * sdk-node and sdk-web on purpose - code that signs an order should not have
 * to know which platform it is running on, which was the whole reason this
 * exists rather than leaving callers to instantiate a provider whose class
 * name differs between the two packages.
 *
 * @export
 * @class PayloadHandler
 */
export class PayloadHandler extends CorePayloadHandler {
  constructor() {
    super(new NodeCryptoProvider());
  }
}
