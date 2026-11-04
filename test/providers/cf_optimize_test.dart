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
    const items = [
      CfScanItem(ip: '104.16.0.2', sent: 2, recv: 2, lossRate: 0, delayMs: 8),
      CfScanItem(ip: '104.16.0.9', sent: 2, recv: 2, lossRate: 0, delayMs: 60),
    ];

    test('pins the head of the list for every selected domain', () {
      expect(buildCfHostEntries(['a.example', 'b.example'], items), {
        'a.example': '104.16.0.2',
        'b.example': '104.16.0.2',
      });
    });

    test('writes nothing without results or domains', () {
      expect(buildCfHostEntries(['a.example'], const []), isEmpty);
      expect(buildCfHostEntries(const [], items), isEmpty);
    });
  });

  group('cfDomainsOutsideRanges', () {
    const detectResults = {
      'in.example': CfDetectItem(domain: 'in.example', inRanges: true),
      'out.example': CfDetectItem(domain: 'out.example'),
      'failed.example': CfDetectItem(domain: 'failed.example', error: 'boom'),
    };

    test('flags only what detect placed outside the ranges', () {
      expect(
        cfDomainsOutsideRanges([
          'in.example',
          'out.example',
          'failed.example',
          'unknown.example',
        ], detectResults),
        ['out.example'],
      );
    });
  });

  group('cfDomainsNotDetected', () {
    const detectResults = {
      'resolved.example': CfDetectItem(
        domain: 'resolved.example',
        inRanges: true,
      ),
      'failed.example': CfDetectItem(domain: 'failed.example', error: 'boom'),
    };

    test('names what no lookup has answered for', () {
      expect(
        cfDomainsNotDetected([
          'resolved.example',
          'failed.example',
          'fresh.example',
        ], detectResults),
        ['failed.example', 'fresh.example'],
      );
    });

    test('every domain is undetected before the first run', () {
      expect(cfDomainsNotDetected(const ['fresh.example'], const {}), [
        'fresh.example',
      ]);
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
