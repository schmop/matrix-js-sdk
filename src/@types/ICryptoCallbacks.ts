/*
Copyright 2021 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

export interface ICryptoCallbacks {
    /**
     * Function to call when a cross-signing private key is needed.
     * Secure Secret Storage will be used by default if this is unset.
     * @param {string} type The type of key needed.  Will be one of "master",
     * "self_signing", or "user_signing"
     * @param {Uint8Array} publicKey The public key matching the expected private
     * key. This can be passed to checkPrivateKey() along with the private key in
     * order to check that a given private key matches what is being requested.
     * @returns {Promise<Uint8Array>} Resolves to the private key, or rejects with error.
     */
    getCrossSigningKey?: (type: string, publicKey: Uint8Array) => Promise<Uint8Array>;
}
