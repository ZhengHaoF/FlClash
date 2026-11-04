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

  Future<void> detect(List<String> domains, List<String> ranges) async {
    if (state.detecting || domains.isEmpty) {
      return;
    }
    state = state.copyWith(detecting: true, error: null);
    try {
      final result = await ref
          .read(coreHandlerProvider)
          .cfDetect(CfDetectParams(domains: domains, ranges: ranges));
      state = state.copyWith(
        detecting: false,
        detectResults: {
          for (final item in result?.results ?? const <CfDetectItem>[])
            item.domain: item,
        },
      );
    } catch (error) {
      state = state.copyWith(detecting: false, error: error.toString());
    }
  }
}

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

/// One address per domain: a hosts entry carrying several is dialed at random,
/// so only the head of the Core's loss-first list is written.
Map<String, String> buildCfHostEntries(
  Iterable<String> domains,
  List<CfScanItem> scanResults,
) {
  if (scanResults.isEmpty) {
    return const {};
  }
  final best = scanResults.first.ip;
  return {for (final domain in domains) domain: best};
}

/// The domains a detect run placed outside Cloudflare's announced ranges:
/// pinning one points a working name at an edge that does not serve it.
List<String> cfDomainsOutsideRanges(
  Iterable<String> domains,
  Map<String, CfDetectItem> detectResults,
) {
  final outside = <String>[];
  for (final domain in domains) {
    final item = detectResults[domain];
    if (item != null && item.error == null && !item.inRanges) {
      outside.add(domain);
    }
  }
  return outside;
}

/// What no lookup has answered for, or answered with an error.
List<String> cfDomainsNotDetected(
  Iterable<String> domains,
  Map<String, CfDetectItem> detectResults,
) {
  final unresolved = <String>[];
  for (final domain in domains) {
    final item = detectResults[domain];
    if (item == null || item.error != null) {
      unresolved.add(domain);
    }
  }
  return unresolved;
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
