import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/proxies/card.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

import '../helpers/test_app.dart';
import '../helpers/test_profiles.dart';

const _testUrl = 'https://example.com/generate_204';
const _pinnedIp = '104.16.0.2';

class _QuietProxiesAction extends ProxiesAction {
  @override
  Future<void> proxyDelayTest(Proxy proxy, [String? testUrl]) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late ProviderContainer container;

  setUp(() {
    container = ProviderContainer(
      overrides: [
        profilesProvider.overrideWith(TestProfiles.new),
        proxiesActionProvider.overrideWith(_QuietProxiesAction.new),
        patchClashConfigProvider.overrideWithBuild(
          (_, _) =>
              const PatchClashConfig(hosts: {'cdn.example.com': _pinnedIp}),
        ),
      ],
    );
    globalState.container = container;
    container.read(viewSizeProvider.notifier).value = const Size(900, 600);
  });

  tearDown(() => container.dispose());

  Future<void> pumpCard(WidgetTester tester, Proxy proxy) async {
    tester.view.physicalSize = const Size(900, 600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: container,
        child: TestApp(
          homeBuilder: (child) => Scaffold(body: child),
          child: SizedBox(
            height: 120,
            child: ProxyCard(
              groupName: 'group',
              testUrl: _testUrl,
              proxy: proxy,
              groupType: GroupType.Selector,
              type: ProxyCardType.standard,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  Finder pinnedMark() => find.byWidgetPredicate(
    (widget) => widget is Tooltip && (widget.message ?? '').contains(_pinnedIp),
  );

  testWidgets('marks the node of a pinned entrance', (tester) async {
    await pumpCard(
      tester,
      const Proxy(
        name: 'proxy 0',
        type: 'Shadowsocks',
        server: 'cdn.example.com',
      ),
    );

    expect(pinnedMark(), findsOneWidget);
  });

  testWidgets('leaves a node without a hosts entry unmarked', (tester) async {
    await pumpCard(
      tester,
      const Proxy(
        name: 'proxy 0',
        type: 'Shadowsocks',
        server: 'other.example.com',
      ),
    );

    expect(pinnedMark(), findsNothing);
  });
}
