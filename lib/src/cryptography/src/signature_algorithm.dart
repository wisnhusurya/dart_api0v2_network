// Copyright 2019-2020 Gohilla Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import '../cryptography.dart';

/// An digital signature algorithm that supports [newKeyPair], [sign],
/// [verify].
///
/// ## Algorithms
///   * [ecdsaP256Sha256]
///   * [ecdsaP384Sha256]
///   * [ecdsaP521Sha256]
///   * [ed25519]
///
/// ## Example
/// An example of using [ed25519]:
/// ```
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   // Sign
///   final keyPair = await ed25519.newKeyPair();
///   final signature = await ed25519.sign(
///     [1,2,3],
///     keyPair,
///   );
///
///   print('Signature bytes: ${signature.bytes}');
///   print('Public key: ${signature.publicKey.bytes}');
///
///   // Anyone can verify the signature
///   final isVerified = await ed25519.verify(
///     [1,2,3],
///     signature,
///   );
/// }
/// ```
abstract class SignatureAlgorithm {
  const SignatureAlgorithm();

  /// A descriptive algorithm name for debugging purposes.
  ///
  /// Examples:
  ///   * "ed25519"
  String get name;

  /// Tells whether [newKeyPairFromSeed] is supported.
  bool get isSeedSupported => false;

  /// Returns public key length (in bytes) or null if many lengths are
  /// supported.
  int get publicKeyLength;

  /// Generates a new random keypair.
  Future<KeyPair> newKeyPair() => Future<KeyPair>.value(newKeyPairSync());

  /// Generates a new random keypair synchronously.
  ///
  /// This method is synchronous and may have lower performance than
  /// asynchronous [newKeyPairSync] because this method can't take advantage of
  /// asynchronous platform API such as _Web Cryptography API_.
  KeyPair newKeyPairSync();

  /// Generates a new keypair from seed. Throws [UnsupportedError] if seeds are
  /// unsupported.
  Future<KeyPair> newKeyPairFromSeed(PrivateKey seed) {
    throw UnsupportedError(
      '$name does not support newKeyPairFromSeed(seed)',
    );
  }

  /// Generates a new keypair from seed. Throws [UnsupportedError] if seeds are
  /// unsupported.
  KeyPair newKeyPairFromSeedSync(PrivateKey seed) {
    throw UnsupportedError(
      '$name does not support newKeyPairFromSeedSync(seed)',
    );
  }

  /// Signs bytes.
  ///
  /// ## Example
  /// An example of using [ed25519]:
  /// ```
  /// import '../cryptography.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a key pair
  ///   final keyPair = await ed25519.newKeyPair();
  ///
  ///   // Sign
  ///   final signature = await ed25519.sign(
  ///     [1,2,3],
  ///     keyPair,
  ///   );
  ///
  ///   // Verify
  ///   final isVerified = await ed25519.verify(
  ///     [1,2,3],
  ///     signature,
  ///   );
  /// }
  /// ```
  Future<Signature> sign(List<int> input, KeyPair keyPair) {
    return Future<Signature>(() => signSync(input, keyPair));
  }

  /// Signs bytes. Unlike [sign], this method is synchronous. Throws
  /// [UnsupportedError] if the operation can not be performed synchronously.
  ///
  /// ## Example
  /// An example of using [ed25519]:
  /// ```
  /// import '../cryptography.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a key pair
  ///   final keyPair = await ed25519.newKeyPair();
  ///
  ///   // Sign
  ///   final signature = await ed25519.sign(
  ///     [1,2,3],
  ///     keyPair,
  ///   );
  ///
  ///   // Verify
  ///   final isVerified = await ed25519.verify(
  ///     [1,2,3],
  ///     signature,
  ///   );
  /// }
  /// ```
  Signature signSync(List<int> input, KeyPair keyPair);

  /// Verifies a signature.
  ///
  /// ## Example
  /// An example of using [ed25519]:
  /// ```
  /// import '../cryptography.dart';
  ///
  /// Future<void> main() async {
  ///   // Generate a key pair
  ///   final keyPair = await ed25519.newKeyPair();
  ///
  ///   // Sign
  ///   final signature = await ed25519.sign(
  ///     [1,2,3],
  ///     keyPair,
  ///   );
  ///
  ///   // Verify
  ///   final isVerified = await ed25519.verify(
  ///     [1,2,3],
  ///     signature,
  ///   );
  /// }
  /// ```
  Future<bool> verify(List<int> input, Signature signature) {
    return Future<bool>(() => verifySync(input, signature));
  }

  /// Verifies a signature. Unlike [verify], this method is synchronous. Throws
  /// [UnsupportedError] if the operation can not be performed synchronously.
  ///
  /// ## Example
  /// An example of using [ed25519]:
  /// ```
  /// import '../cryptography.dart';
  ///
  /// void main() {
  ///   // Generate a key pair
  ///   final keyPair = await ed25519.newKeyPair();
  ///
  ///   // Sign
  ///   final signature = await ed25519.signSync(
  ///     [1,2,3],
  ///     keyPair,
  ///   );
  ///
  ///   // Verify
  ///   final isVerified = await ed25519.verifySync(
  ///     [1,2,3],
  ///     signature,
  ///   );
  /// }
  /// ```
  bool verifySync(List<int> input, Signature signature);
}
