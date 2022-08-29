import 'package:dart_api0v2_network/dart_api0v2_network.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    test('(General) Execute checkInternetConnection', () async {
      API0Network.config['url'] = "https://mbank-stag.bjbs.id/";
      expect(() async {
        return await API0Network.checkInternetConnection();
      }, returnsNormally);
    });
  });
}
