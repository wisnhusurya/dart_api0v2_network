import 'package:dart_api0v2_network/dart_api0v2_network.dart';

void main() async {
  API0Network.config['url'] = "https://mbank-stag.bjbs.id/";
  await API0Network.checkInternetConnection();
  print('Internet OK');
}
