import 'package:fl_clash/common/constant.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/cf_optimize.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('extractProfileServerDomains', () {
    test('keeps server domains and drops IP literals', () {
      const content = '''
proxies:
  - name: a
    type: vless
    server: cdn.example.com
    port: 443
  - name: b
    type: trojan
    server: 104.16.0.1
    port: 443
  - name: c
    type: vmess
    server: cdn.example.com
    port: 2053
''';
      expect(extractProfileServerDomains(content), ['cdn.example.com']);
    });

    test('survives malformed yaml and documents without proxies', () {
      expect(extractProfileServerDomains(' ::: broken'), isEmpty);
      expect(extractProfileServerDomains('port: 7890'), isEmpty);
      expect(extractProfileServerDomains('proxies: []'), isEmpty);
    });

    test('ignores entries without a server string', () {
      const content = '''
proxies:
  - name: a
  - 12
  - server: 3
''';
      expect(extractProfileServerDomains(content), isEmpty);
    });
  });

  group('cfScanGuardDuration', () {
    test('mirrors the core defaults', () {
      final guard = cfScanGuardDuration(const CfScanParams(port: '443'));
      // 500 samples at the core default concurrency of 100 round to 5 rounds
      // x 1500 ms x 2 attempts + 5 s.
      expect(guard, const Duration(seconds: 20));
    });

    test('clamps extreme parameters under the core ceiling', () {
      final guard = cfScanGuardDuration(
        const CfScanParams(
          port: '443',
          sampleCount: 4096,
          concurrency: 1,
          testCount: 10,
          timeout: 10000,
        ),
      );
      // The core caps its own deadline at two minutes; the guard must not
      // fire before that has had its chance.
      expect(guard, const Duration(milliseconds: 125000));
    });
  });

  group('cfDetectBudgetFactor', () {
    test('covers the concurrency rounds and clamps', () {
      expect(cfDetectBudgetFactor(const CfDetectParams(domains: [])), 1);
      expect(
        cfDetectBudgetFactor(const CfDetectParams(domains: ['a', 'b', 'c'])),
        1,
      );
      expect(
        cfDetectBudgetFactor(CfDetectParams(domains: List.filled(9, 'a'))),
        2,
      );
      expect(
        cfDetectBudgetFactor(CfDetectParams(domains: List.filled(100, 'a'))),
        8,
      );
    });
  });

  group('cfTestIpsGuardDuration', () {
    test('mirrors the core defaults', () {
      final guard = cfTestIpsGuardDuration(
        const CfTestIpsParams(
          targets: [
            CfTestIpsTarget(domain: 'a.example', ips: ['1.1.1.1', '1.1.1.2']),
          ],
          port: '443',
        ),
      );
      // 2 addresses at the core default concurrency of 100 round to 1 round
      // x 1500 ms x 2 attempts + 5 s.
      expect(guard, const Duration(seconds: 8));
    });

    test('caps the counted addresses the way the core does', () {
      final guard = cfTestIpsGuardDuration(
        CfTestIpsParams(
          targets: [
            CfTestIpsTarget(
              domain: 'a.example',
              ips: List.filled(64, '1.1.1.1'),
            ),
          ],
          port: '443',
        ),
      );
      // The core caps a domain at sixteen addresses; sixteen at concurrency
      // 100 still round to 1.
      expect(guard, const Duration(seconds: 8));
    });

    test('clamps extreme parameters under the core ceiling', () {
      final guard = cfTestIpsGuardDuration(
        CfTestIpsParams(
          targets: [
            for (var i = 0; i < 64; i++)
              CfTestIpsTarget(
                domain: 'd$i.example',
                ips: List.filled(16, '1.1.1.1'),
              ),
          ],
          port: '443',
          concurrency: 1,
          testCount: 10,
          timeout: 10000,
        ),
      );
      // The core caps its own deadline at two minutes; the guard must not
      // fire before that has had its chance.
      expect(guard, const Duration(milliseconds: 125000));
    });
  });

  group('cfResolveGuardDuration', () {
    test('mirrors the core defaults', () {
      final guard = cfResolveGuardDuration(
        const CfResolveParams(domains: ['a.example']),
      );
      // One sweep of eight at the core default 3000 ms per query + 5 s.
      expect(guard, const Duration(seconds: 8));
    });

    test('caps the swept domains the way the core does', () {
      final guard = cfResolveGuardDuration(
        CfResolveParams(domains: List.filled(100, 'a.example')),
      );
      // Sixty-four domains round to 8 sweeps x 3000 ms + 5 s.
      expect(guard, const Duration(seconds: 29));
    });
  });

  group('CfOptimizeState', () {
    test('detect results replace wholesale on copyWith', () {
      const state = CfOptimizeState(
        detectResults: {
          'a.example': CfDetectItem(domain: 'a.example', inRanges: true),
        },
      );
      final updated = state.copyWith(
        detecting: true,
        detectResults: {
          'b.example': const CfDetectItem(domain: 'b.example', inRanges: false),
        },
      );
      expect(updated.detectResults.keys, ['b.example']);
      expect(updated.detecting, isTrue);
      expect(updated.scanResult, isNull);
    });
  });

  group('filterCfScanItems', () {
    const items = [
      CfScanItem(ip: '104.16.0.1', sent: 2, recv: 2, lossRate: 0, delayMs: 8),
      CfScanItem(ip: '104.16.0.2', sent: 2, recv: 2, lossRate: 0, delayMs: 60),
      CfScanItem(
        ip: '104.16.0.3',
        sent: 2,
        recv: 1,
        lossRate: 0.5,
        delayMs: 30,
      ),
      CfScanItem(ip: '104.16.0.4', sent: 2, recv: 2, lossRate: 0, delayMs: 400),
    ];

    test('a bound at zero is off', () {
      expect(filterCfScanItems(items).length, 4);
    });

    test('the lower bound drops the fake-fast hop', () {
      expect(filterCfScanItems(items, minDelay: 10).map((item) => item.ip), [
        '104.16.0.2',
        '104.16.0.3',
        '104.16.0.4',
      ]);
    });

    test('the upper and loss bounds narrow the list in place', () {
      expect(filterCfScanItems(items, maxDelay: 100).map((item) => item.ip), [
        '104.16.0.1',
        '104.16.0.2',
        '104.16.0.3',
      ]);
      expect(
        filterCfScanItems(items, maxLossPercent: 10).map((item) => item.ip),
        ['104.16.0.1', '104.16.0.2', '104.16.0.4'],
      );
      expect(
        filterCfScanItems(
          items,
          minDelay: 10,
          maxDelay: 100,
          maxLossPercent: 10,
        ).map((item) => item.ip),
        ['104.16.0.2'],
      );
    });
  });

  group('buildCfHostEntries', () {
    const scanItems = [
      CfScanItem(ip: '104.16.0.2', sent: 2, recv: 2, lossRate: 0, delayMs: 8),
      CfScanItem(ip: '104.16.0.9', sent: 2, recv: 2, lossRate: 0, delayMs: 60),
    ];
    const detectResults = {
      'in.example': CfDetectItem(domain: 'in.example', inRanges: true),
      'out.example': CfDetectItem(domain: 'out.example'),
    };

    test('pins the fastest tested answer per domain', () {
      expect(
        buildCfHostEntries(
          ['a.example', 'b.example'],
          scanResults: const [],
          testResults: const {
            'a.example': [
              CfScanItem(ip: '1.1.1.1', lossRate: 0, delayMs: 30),
              CfScanItem(ip: '1.1.1.2', lossRate: 0, delayMs: 10),
            ],
            'b.example': [CfScanItem(ip: '2.2.2.2', lossRate: 0.5, delayMs: 1)],
          },
          detectResults: const {},
        ),
        {'a.example': '1.1.1.2', 'b.example': '2.2.2.2'},
      );
    });

    test('a domain inside the ranges also draws on the scan answers', () {
      expect(
        buildCfHostEntries(
          ['in.example'],
          scanResults: scanItems,
          testResults: const {
            'in.example': [
              CfScanItem(ip: '9.9.9.9', lossRate: 0, delayMs: 100),
            ],
          },
          detectResults: detectResults,
        ),
        // The scan's 8 ms beats the tested 100 ms.
        {'in.example': '104.16.0.2'},
      );
    });

    test('a domain outside the ranges never gets a scan answer', () {
      expect(
        buildCfHostEntries(
          ['out.example'],
          scanResults: scanItems,
          testResults: const {},
          detectResults: detectResults,
        ),
        isEmpty,
      );
    });

    test(
      'an outside domain without a measured answer pins its own address',
      () {
        expect(
          buildCfHostEntries(
            ['out.example'],
            scanResults: scanItems,
            testResults: const {},
            detectResults: {
              ...detectResults,
              'out.example': const CfDetectItem(
                domain: 'out.example',
                ips: ['43.207.158.98'],
              ),
            },
          ),
          {'out.example': '43.207.158.98'},
        );
      },
    );

    test('the fallback prefers the routable IPv4 answer', () {
      expect(
        buildCfHostEntries(
          ['v6.example'],
          scanResults: const [],
          testResults: const {},
          detectResults: const {
            'v6.example': CfDetectItem(
              domain: 'v6.example',
              ips: ['2401:b60:35::1', '43.207.158.98'],
            ),
          },
        ),
        {'v6.example': '43.207.158.98'},
      );
    });

    test('a failed lookup is never pinned', () {
      expect(
        buildCfHostEntries(
          ['failed.example'],
          scanResults: const [],
          testResults: const {},
          detectResults: const {
            'failed.example': CfDetectItem(
              domain: 'failed.example',
              error: 'boom',
              ips: ['1.2.3.4'],
            ),
          },
        ),
        isEmpty,
      );
    });

    test('writes nothing without results or domains', () {
      expect(
        buildCfHostEntries(
          ['a.example'],
          scanResults: const [],
          testResults: const {},
          detectResults: const {},
        ),
        isEmpty,
      );
      expect(
        buildCfHostEntries(
          const [],
          scanResults: scanItems,
          testResults: const {},
          detectResults: const {},
        ),
        isEmpty,
      );
    });
  });

  group('parseCfRangeList', () {
    test('keeps the published order and drops duplicates', () {
      const raw = '''
173.245.48.0/20
103.21.244.0/22

173.245.48.0/20
 104.16.0.0/13 
''';
      expect(parseCfRangeList(raw), [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '104.16.0.0/13',
      ]);
    });

    test('drops IPv6 prefixes, since only IPv4 is sampled', () {
      const raw = '104.16.0.0/13\n2400:cb00::/32\n2606:4700::/32';
      expect(parseCfRangeList(raw), ['104.16.0.0/13']);
    });

    test('drops lines the Core would refuse', () {
      const raw = '''
not-a-prefix
104.16.0.0
104.16.0.0/33
104.16.0.0/-1
104.16.0.0/+8
104.300.0.0/13
104.16.0.0/13 # tail
''';
      expect(parseCfRangeList(raw), isEmpty);
    });

    test('caps an over-long answer', () {
      final raw = List.generate(300, (index) => '10.0.$index.0/32').join('\n');
      expect(parseCfRangeList(raw).length, 256);
    });

    test('an empty answer yields nothing', () {
      expect(parseCfRangeList(''), isEmpty);
    });
  });

  group('effectiveCfRanges', () {
    test('falls back to the bundled pool until an update lands', () {
      expect(effectiveCfRanges(const []), defaultCfRanges);
    });

    test('uses what the update cached', () {
      expect(effectiveCfRanges(const ['104.16.0.0/13']), ['104.16.0.0/13']);
    });
  });

  group('pinnedHostsEntryForHost', () {
    test('matches a plain key only for the exact host', () {
      const hosts = {'a.example.com': '1.2.3.4'};
      expect(pinnedHostsEntryForHost(hosts, 'a.example.com'), '1.2.3.4');
      expect(pinnedHostsEntryForHost(hosts, 'b.example.com'), isNull);
      expect(pinnedHostsEntryForHost(hosts, 'example.com'), isNull);
    });

    test('follows the wildcard keys mihomo accepts', () {
      const hosts = {'*.one.example': '1.2.3.4', '.two.example': '5.6.7.8'};
      expect(pinnedHostsEntryForHost(hosts, 'a.one.example'), '1.2.3.4');
      expect(pinnedHostsEntryForHost(hosts, 'a.b.one.example'), isNull);
      expect(pinnedHostsEntryForHost(hosts, 'one.example'), isNull);
      expect(pinnedHostsEntryForHost(hosts, 'a.two.example'), '5.6.7.8');
      expect(pinnedHostsEntryForHost(hosts, 'a.b.two.example'), '5.6.7.8');
      // A leading-dot key covers what sits under it, not the name itself.
      expect(pinnedHostsEntryForHost(hosts, 'two.example'), isNull);
    });

    test('prefers the exact key over a wildcard', () {
      const hosts = {'a.example.com': '1.1.1.1', '*.example.com': '2.2.2.2'};
      expect(pinnedHostsEntryForHost(hosts, 'a.example.com'), '1.1.1.1');
      expect(pinnedHostsEntryForHost(hosts, 'c.example.com'), '2.2.2.2');
    });

    test('ignores a value that is not an address', () {
      expect(
        pinnedHostsEntryForHost({
          'a.example.com': '1.1.1.1,2.2.2.2',
        }, 'a.example.com'),
        isNull,
      );
      expect(
        pinnedHostsEntryForHost({
          'a.example.com': 'other.example.com',
        }, 'a.example.com'),
        isNull,
      );
    });

    test('skips a key the core refuses to insert', () {
      expect(
        pinnedHostsEntryForHost({'a..example.com': '1.2.3.4'}, 'a.example.com'),
        isNull,
      );
      expect(
        pinnedHostsEntryForHost({
          'a*.example.com': '1.2.3.4',
        }, 'ab.example.com'),
        isNull,
      );
      // An empty label is the subtree key, which would match anything else too.
      expect(
        pinnedHostsEntryForHost({' ': '1.2.3.4'}, 'a.example.com'),
        isNull,
      );
    });

    // The host comes from a subscription, so its label count is not ours to
    // bound: the walk costs the hosts map, never the length of the name.
    test('a long host stays a keystroke away', () {
      const hosts = {'cdn.example.com': '104.16.0.2'};
      final host = '${List.filled(24, 'node').join('.')}.cdn.example.com';
      final started = Stopwatch()..start();
      for (var i = 0; i < 500; i++) {
        expect(pinnedHostsEntryForHost(hosts, host), isNull);
      }
      expect(started.elapsed, lessThan(const Duration(seconds: 2)));
    });
  });
}
