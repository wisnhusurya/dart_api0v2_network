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

import 'dart:typed_data';

import '../../cryptography.dart';
import 'ec_ed25519_impl.dart';
import 'ec_x25519_impl.dart';

/// _X25519_ ([RFC 7748](https://tools.ietf.org/html/rfc7748)) key exchange
/// algorithm (Curve25519 Diffie-Hellman).
///
/// ## Things to know
///   * Private key is any 32-byte sequence.
///   * Public key is 32 bytes.
///
/// ## Example
/// ```dart
/// import '../cryptography.dart';
///
/// Future<void> main() async {
///   // Let's generate two keypairs.
///   final localKeyPair = await x25519.newKeyPair();
///   final remoteKeyPair = await x5519.newKeyPair();
///
///   // We can now calculate a shared secret
///   var sharedSecret = await x25519.sharedSecret(
///     localPrivateKey: localKeyPair.privateKey,
///     remotePublicKey: remoteKeyPair.publicKey,
///   );
/// }
/// ```
const KeyExchangeAlgorithm x25519 = _X25519();

class _X25519 extends KeyExchangeAlgorithm {
  /// Constant 9.
  static final Uint8List _constant9 = () {
    final result = Uint8List(32);
    result[0] = 9;
    return result;
  }();

  /// Constant 121665 (0x1db41).
  static final Int32List _constant121665 = () {
    final result = Int32List(16);
    result[0] = 0xdb41;
    result[1] = 1;
    return result;
  }();

  const _X25519();

  @override
  String get name => 'x25519';

  @override
  int get publicKeyLength => 32;

  @override
  KeyPair newKeyPairFromSeedSync(PrivateKey seed) {
    ArgumentError.checkNotNull(seed, 'privateKey');
    final seedBytes = Uint8List.fromList(seed.extractSync());
    if (seedBytes.length != 32) {
      throw ArgumentError(
        'Seed has invalid length: ${seedBytes.length}',
      );
    }

    // Create a secret key
    _X25519.replaceSeedWithSecretKey(seedBytes);
    final privateKey = PrivateKey(seedBytes);

    // Calculate public key
    final publicKeyBytes = Uint8List(32);
    _X25519._calculate(publicKeyBytes, seedBytes, _X25519._constant9);

    // Return a keypair
    final publicKey = PublicKey(publicKeyBytes);
    return KeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  @override
  KeyPair newKeyPairSync() {
    return newKeyPairFromSeedSync(
      PrivateKey.randomBytes(32),
    );
  }

  @override
  SecretKey sharedSecretSync({
    required PrivateKey localPrivateKey,
    required PublicKey remotePublicKey,
  }) {
    final secretKeyUint8List = Uint8List.fromList(
      localPrivateKey.extractSync(),
    );
    replaceSeedWithSecretKey(secretKeyUint8List);
    final result = Uint8List(32);
    _calculate(
      result,
      secretKeyUint8List,
      Uint8List.fromList(remotePublicKey.bytes),
    );
    return SecretKey(result);
  }

  /// Modifies certain bits of seed so that the result is a valid secret key.
  static void replaceSeedWithSecretKey(List<int> seed) {
    // First 3 bits must be 0
    seed[0] &= 0xf8;

    // Bit 254 must be 1
    seed[31] |= 0x40;

    // Bit 255 must be 0
    seed[31] &= 0x7f;
  }

  static void _calculate(
    Uint8List result,
    Uint8List secretKey,
    Uint8List publicKey,
  ) {
    // Unpack public key into the internal Int32List
    final unpackedPublicKey = (Register25519()..setBytes(publicKey)).data;

    // Clear the last bit
    unpackedPublicKey[15] &= 0x7FFF;

    // Allocate arrays
    final a = Int32List(16);
    final b = Int32List(16);
    final c = Int32List(16);
    final d = Int32List(16);
    final e = Int32List(16);
    final f = Int32List(16);

    // See RFC 7748:
    // "Elliptic Curves for Security"
    // https://tools.ietf.org/html/rfc7748
    //
    // Initialize variables.
    //
    // `secretKey` = RFC parameter `k`
    // `unpackedPublicKey` = RFC parameter `u`
    // `a` = RFC assignment `x_2 = 1`
    // `b` = RFC assignment `z_3 = u`
    // `c` = RFC assignment `z_2 = 0`
    // `d` = RFC assignment `z_3 = 1`
    a[0] = 1;
    d[0] = 1;
    for (var i = 0; i < 16; i++) {
      b[i] = unpackedPublicKey[i];
    }

    // For bits 255..0
    for (var t = 254; t >= 0; t--) {
      // Get the secret key bit
      final iKI = 1 & (secretKey[t >> 3] >> (7 & t));

      // Two conditional swaps.
      //
      // In the RFC:
      //   `a` is `x_2`
      //   `b` is `x_3`
      //   `c` is `z_2`
      //   `d` is `z_3`
      _conditionalSwap(a, b, iKI);
      _conditionalSwap(c, d, iKI);

      // Perform +/- operation.
      // We don't need to handle carry bits. Later multiplication will take
      // care of values that have become more than 16 bits.
      for (var i = 0; i < 16; i++) {
        final aAI = a[i];
        final bBI = b[i];
        final cCI = c[i];
        final dDI = d[i];

        // `e` = RFC assignment `A = x_2 + z_2`
        e[i] = aAI + cCI;

        // `a` = RFC assignment `B = x_2 - z_2`
        a[i] = aAI - cCI;

        // `c` = RFC assignment `C = x_3 + z_3`
        c[i] = bBI + dDI;

        // `d` = RFC assignment `D = x_3 - z_3`
        b[i] = bBI - dDI;
      }

      // d = RFC assignment `AA = A^2`
      mod38Mul(d, e, e);

      // f = RFC assignment `BB = B^2`
      mod38Mul(f, a, a);

      // a = RFC assignment `DA = D * A`
      mod38Mul(a, c, a);

      // b = RFC assignment `CB = C * B`
      mod38Mul(c, b, e);

      // In the RFC:
      // x_3 = (DA + CB)^2
      // z_3 = x_1 * (DA - CB)^2
      for (var i = 0; i < 16; i++) {
        final ai = a[i];
        final ci = c[i];
        e[i] = ai + ci;
        a[i] = ai - ci;
        c[i] = d[i] - f[i];
      }

      // b = RFC expression `(DA - CB)^2`
      //
      // Argument `a` = RFC expression `(DA - CB)`
      mod38Mul(b, a, a);

      // a = RFC expression `a24 * E`
      //
      // Argument `c` = RFC expression `E`
      mod38Mul(a, _constant121665, c);

      // a = RFC expression `(AA + a24 * E)`
      //
      // Argument `a` = RFC expression `a24 * E`
      // Argument `d` = RFC expression `AA`
      for (var i = 0; i < 16; i++) {
        a[i] += d[i];
      }

      // c = RFC assignment `z_2 = E * (AA + a24 * E)`
      //
      // Argument `a` = RFC expression `(AA + a24 * E)`
      // Argument `c` = RFC expression `E`
      mod38Mul(c, a, c);

      // a = RFC assignment `x_2 = AA * BB`
      //
      // Argument `d` = RFC expression `AA`
      // Argument `f` = RFC expression `BB`
      mod38Mul(a, d, f);

      // d = RFC assignment `z_3 = x_1 * (DA - CB)^2`
      mod38Mul(d, unpackedPublicKey, b);

      // Remaining calculations.
      //
      // See:
      // "High-speed Curve25519 on 8-bit, 16-bit, and 32-bit microcontrollers"
      // https://link.springer.com/article/10.1007/s10623-015-0087-1
      mod38Mul(b, e, e);
      _conditionalSwap(a, b, iKI);
      _conditionalSwap(c, d, iKI);
    }

    // Remaining calculations.
    //
    // See:
    // "High-speed Curve25519 on 8-bit, 16-bit, and 32-bit microcontrollers"
    // https://link.springer.com/article/10.1007/s10623-015-0087-1

    // d = c
    for (var i = 0; i < 16; i++) {
      d[i] = c[i];
    }

    for (var i = 253; i >= 0; i--) {
      mod38Mul(c, c, c);
      if (i != 2 && i != 4) {
        mod38Mul(c, c, d);
      }
    }
    mod38Mul(a, a, c);
    for (var i = 0; i < 3; i++) {
      var x = 1;
      for (var i = 0; i < 16; i++) {
        final v = 0xFFFF + a[i] + x;
        x = v ~/ 0x10000;
        a[i] = v - 0x10000 * x;
      }
      a[0] += 38 * (x - 1);
    }
    for (var i = 0; i < 2; i++) {
      var previous = a[0] - 0xFFED;
      b[0] = 0xFFFF & previous;
      for (var j = 1; j < 15; j++) {
        final current = a[j] - 0xFFFF - (1 & (previous >> 16));
        b[j] = 0xFFFF & current;
        previous = current;
      }
      b[15] = a[15] - 0x7FFF - (1 & (previous >> 16));
      final isSwap = 1 - (1 & (b[15] >> 16));
      _conditionalSwap(a, b, isSwap);
    }

    // Pack the internal Int32List into result bytes
    Register25519(a).toBytes(result);
  }

  // Constant-time conditional swap.
  //
  // If b is 0, the function does nothing.
  // If b is 1, elements of the arrays will be swapped.
  static void _conditionalSwap(Int32List p, Int32List q, int b) {
    final c = ~(b - 1);
    for (var i = 0; i < 16; i++) {
      final t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }
}
