import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter/foundation.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:yaml/yaml.dart';

import 'config.dart';
import 'core.dart';

part 'generated/cf_optimize.g.dart';

@Riverpod(keepAlive: true)
class CfOptimize extends _$CfOptimize {
  @override
  CfOptimizeState build() => const CfOptimizeState();

  Future<void> scan(CfScanParams params) async {
    if (state.scanning) {
      return;
    }
    state = state.copyWith(scanning: true, error: null);
    try {
      final result = await ref.read(coreHandlerProvider).cfScan(params);
      state = state.copyWith(
        scanning: false,
        scanResult: result,
        scannedAt: DateTime.now(),
      );
    } catch (error) {
      state = state.copyWith(scanning: false, error: error.toString());
    }
  }

  Future<void> detect(
    List<String> domains,
    List<String> ranges, {
    required String port,
  }) async {
    if (state.detecting || domains.isEmpty) {
      return;
    }
    state = state.copyWith(detecting: true, error: null, testResults: const {});
    try {
      // The app's resolver and a sweep of public resolvers answer side by
      // side: the union pools edges no single resolver hands out, which is
      // what lets a domain outside Cloudflare's ranges find a reachable
      // entrance at all.
      final (detected, resolved) = await (
        ref
            .read(coreHandlerProvider)
            .cfDetect(CfDetectParams(domains: domains, ranges: ranges)),
        ref
            .read(coreHandlerProvider)
            .cfResolve(CfResolveParams(domains: domains)),
      ).wait;
      final detectResults = {
        for (final item in detected?.results ?? const <CfDetectItem>[])
          item.domain: item,
      };
      state = state.copyWith(detectResults: detectResults);
      final pool = <String, List<String>>{};
      void addIps(String domain, Iterable<String> ips) {
        pool[domain] = {...pool[domain] ?? const <String>[], ...ips}.toList();
      }

      for (final item in detectResults.values) {
        if (item.ips.isNotEmpty) {
          addIps(item.domain, item.ips);
        }
      }
      for (final item in resolved?.results ?? const <CfResolveItem>[]) {
        if (item.ips.isNotEmpty) {
          addIps(item.domain, item.ips);
        }
      }
      final targets = [
        for (final entry in pool.entries)
          CfTestIpsTarget(domain: entry.key, ips: entry.value),
      ];
      if (targets.isEmpty) {
        state = state.copyWith(detecting: false);
        return;
      }
      // The lookups just answered over the same path a node's dial takes, so
      // the addresses are measured while they are fresh.
      final tested = await ref
          .read(coreHandlerProvider)
          .cfTestIps(
            CfTestIpsParams(
              targets: targets,
              port: port,
              concurrency: 128,
              testCount: 2,
              timeout: 1500,
            ),
          );
      state = state.copyWith(
        detecting: false,
        testResults: {
          for (final item in tested?.results ?? const <CfTestIpsItem>[])
            if (item.results.isNotEmpty) item.domain: item.results,
        },
      );
    } catch (error) {
      state = state.copyWith(detecting: false, error: error.toString());
    }
  }

  /// Fetches Cloudflare's published list and keeps it in the app settings. A
  /// failed fetch leaves the previous list in place, so the page never falls
  /// back to a smaller pool behind the user's back; the bundled pool only
  /// serves until the first successful update.
  Future<void> updateRanges() async {
    if (state.updatingRanges || state.scanning) {
      return;
    }
    state = state.copyWith(updatingRanges: true, rangesError: null);
    try {
      final response = await request.getTextResponseForUrl(cfRangesV4Url);
      final ranges = parseCfRangeList(response.data ?? '');
      if (ranges.isEmpty) {
        throw const FormatException('no IPv4 prefix in the answer');
      }
      ref
          .read(appSettingProvider.notifier)
          .update(
            (setting) => setting.copyWith(
              cfRangesV4: ranges,
              cfRangesFetchedAt: DateTime.now().millisecondsSinceEpoch,
            ),
          );
      // The kept answers were measured against the ranges just replaced.
      state = const CfOptimizeState();
    } catch (error) {
      state = state.copyWith(
        updatingRanges: false,
        rangesError: error.toString(),
      );
    }
  }
}

/// The ranges a scan or a detect run uses: what the last update cached, or the
/// bundled pool while nothing has been fetched yet.
List<String> effectiveCfRanges(List<String> cached) {
  return cached.isEmpty ? defaultCfRanges : cached;
}

/// Keeps the IPv4 prefixes in the answer, in order and deduplicated. The Core
/// fails a whole scan on one unusable range, so anything else - a v6 prefix, a
/// malformed line, an over-long answer - is dropped here instead.
List<String> parseCfRangeList(String raw) {
  final seen = <String>{};
  final ranges = <String>[];
  for (final line in const LineSplitter().convert(raw)) {
    final value = line.trim();
    if (!isCidr(value)) {
      continue;
    }
    final address = value.substring(0, value.lastIndexOf('/'));
    if (InternetAddress.tryParse(address)?.type != InternetAddressType.IPv4) {
      continue;
    }
    if (!seen.add(value)) {
      continue;
    }
    ranges.add(value);
    if (ranges.length == _maxCfRanges) {
      break;
    }
  }
  return ranges;
}

/// Cloudflare publishes tens of prefixes; a cap keeps a wrong or hostile
/// answer from turning into the pool every later scan samples.
const _maxCfRanges = 256;

/// The server domains the profile's own proxies dial, parsed in an isolate.
/// A provider's proxies stay behind its URL, so they are not candidates here.
@Riverpod(keepAlive: false)
Future<List<String>> cfProfileDomains(Ref ref) async {
  final profileId = ref.watch(currentProfileIdProvider);
  if (profileId == null) {
    return const [];
  }
  final path = await appPath.getProfilePath(profileId.toString());
  final file = File(path);
  if (!await file.exists()) {
    return const [];
  }
  final content = await file.readAsString();
  return compute(extractProfileServerDomains, content);
}

List<String> extractProfileServerDomains(String content) {
  Object? document;
  try {
    document = loadYaml(content);
  } catch (_) {
    return const [];
  }
  if (document is! Map) {
    return const [];
  }
  final proxies = document['proxies'];
  if (proxies is! List) {
    return const [];
  }
  final domains = <String>{};
  for (final proxy in proxies) {
    if (proxy is! Map) {
      continue;
    }
    final server = proxy['server'];
    if (server is! String || server.isEmpty) {
      continue;
    }
    if (InternetAddress.tryParse(server) != null) {
      continue;
    }
    domains.add(server);
  }
  return domains.toList(growable: false);
}

/// One address per domain: a hosts entry carrying several is dialed at random.
/// A domain's candidates are the addresses its own DNS answered with and the
/// Core measured, plus the scan's answers when the domain sits inside
/// Cloudflare's ranges; the fastest candidate wins.
Map<String, String> buildCfHostEntries(
  Iterable<String> domains, {
  required List<CfScanItem> scanResults,
  required Map<String, List<CfScanItem>> testResults,
  required Map<String, CfDetectItem> detectResults,
}) {
  final entries = <String, String>{};
  for (final domain in domains) {
    final item = detectResults[domain];
    final candidates = [
      ...testResults[domain] ?? const <CfScanItem>[],
      if (item != null && item.error == null && item.inRanges) ...scanResults,
    ];
    if (candidates.isEmpty) {
      continue;
    }
    candidates.sort(compareCfScanItems);
    entries[domain] = candidates.first.ip;
  }
  return entries;
}

/// The Core's loss-first ranking: loss rate, then delay, then the address.
int compareCfScanItems(CfScanItem a, CfScanItem b) {
  if (a.lossRate != b.lossRate) {
    return a.lossRate.compareTo(b.lossRate);
  }
  if (a.delayMs != b.delayMs) {
    return a.delayMs.compareTo(b.delayMs);
  }
  return a.ip.compareTo(b.ip);
}

/// Mirrors mihomo's hosts trie: a literal label wins, then `*`, then a
/// leading-dot subtree. Descending only into children the keys have keeps the
/// walk linear in the map, not in the host's label count.
String? pinnedHostsEntryForHost(Map<String, String> hosts, String host) {
  final labels = _hostLabels(host);
  if (hosts.isEmpty || labels == null) {
    return null;
  }
  final root = _HostsNode();
  for (final entry in hosts.entries) {
    final value = entry.value.trim();
    if (InternetAddress.tryParse(value) == null) {
      continue;
    }
    final parts = _hostsKeyParts(entry.key);
    if (parts != null) {
      _insertHostsKey(root, parts, value);
    }
  }
  return _searchHosts(root, labels);
}

List<String>? _hostLabels(String host) {
  final trimmed = host.trim().toLowerCase();
  if (trimmed.isEmpty || trimmed.endsWith('.')) {
    return null;
  }
  final labels = trimmed.split('.');
  return labels.any((label) => label.isEmpty) ? null : labels;
}

/// Null when mihomo would refuse to insert the key; `+.` stays unmatched.
List<String>? _hostsKeyParts(String key) {
  final trimmed = key.trim().toLowerCase();
  if (trimmed.isEmpty || trimmed.endsWith('.')) {
    return null;
  }
  final labels = trimmed.split('.');
  if (labels.length > 1 && labels.skip(1).any((label) => label.isEmpty)) {
    return null;
  }
  if (labels.any((label) => label.contains('*') && label != '*')) {
    return null;
  }
  return labels;
}

void _insertHostsKey(_HostsNode root, List<String> labels, String value) {
  var node = root;
  for (final label in labels.reversed) {
    node = node.children.putIfAbsent(label, _HostsNode.new);
  }
  node.value = value;
}

String? _searchHosts(_HostsNode node, List<String> labels) {
  if (labels.isEmpty) {
    return node.value;
  }
  final rest = labels.sublist(0, labels.length - 1);
  for (final child in [node.children[labels.last], node.children['*']]) {
    if (child != null) {
      final hit = _searchHosts(child, rest);
      if (hit != null) {
        return hit;
      }
    }
  }
  return node.children['']?.value;
}

class _HostsNode {
  final children = <String, _HostsNode>{};
  String? value;
}

/// The page's filter over a scan's answers; a bound at or below zero is off.
List<CfScanItem> filterCfScanItems(
  List<CfScanItem> items, {
  int minDelay = 0,
  int maxDelay = 0,
  int maxLossPercent = 0,
}) {
  final maxLoss = maxLossPercent <= 0 ? null : maxLossPercent / 100;
  return [
    for (final item in items)
      if ((minDelay <= 0 || item.delayMs >= minDelay) &&
          (maxDelay <= 0 || item.delayMs <= maxDelay) &&
          (maxLoss == null || item.lossRate <= maxLoss))
        item,
  ];
}
