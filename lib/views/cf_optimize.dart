import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/features/form/form.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

class CfOptimizeView extends ConsumerStatefulWidget {
  const CfOptimizeView({super.key});

  @override
  ConsumerState<CfOptimizeView> createState() => _CfOptimizeViewState();
}

class _CfOptimizeViewState extends ConsumerState<CfOptimizeView> {
  // Kept in step with the clamps in cf_scan.go, which refuses a sample count
  // outside this range and falls back to its own default.
  static const _minSampleCount = 1;
  static const _maxSampleCount = 4096;
  static const _defaultSampleCount = 512;

  final _portController = TextEditingController(text: '443');
  final _sampleCountController = TextEditingController(text: '512');
  final _minDelayController = TextEditingController(text: '10');
  final _maxDelayController = TextEditingController(text: '200');
  final _maxLossController = TextEditingController(text: '50');
  final _domainController = TextEditingController();
  final _selectedDomains = <String>{};
  final _manualDomains = <String>{};
  var _portInvalid = false;
  var _sampleCountInvalid = false;

  // A filter keystroke only redraws the results section; the candidate list
  // below it is the page's biggest subtree.
  final _filterRevision = ValueNotifier<int>(0);

  @override
  void initState() {
    super.initState();
    for (final controller in [
      _minDelayController,
      _maxDelayController,
      _maxLossController,
    ]) {
      controller.addListener(_handleFilterChanged);
    }
  }

  // The filter sits over the answers a scan already returned, so moving a
  // bound redraws the list instead of asking the Core again.
  void _handleFilterChanged() => _filterRevision.value++;

  @override
  void dispose() {
    _portController.dispose();
    _sampleCountController.dispose();
    _minDelayController.dispose();
    _maxDelayController.dispose();
    _maxLossController.dispose();
    _domainController.dispose();
    _filterRevision.dispose();
    super.dispose();
  }

  int? _intValue(String raw) => int.tryParse(raw.trim());

  int _sampleCount() {
    return _intValue(_sampleCountController.text) ?? _defaultSampleCount;
  }

  // An empty field keeps the default; anything typed outside the Core's range
  // is flagged rather than silently clamped behind the user's back.
  bool get _sampleCountValid {
    if (_sampleCountController.text.trim().isEmpty) {
      return true;
    }
    final value = _intValue(_sampleCountController.text);
    return value != null &&
        value >= _minSampleCount &&
        value <= _maxSampleCount;
  }

  List<CfScanItem> _filteredItems(List<CfScanItem> items) {
    return filterCfScanItems(
      items,
      minDelay: _intValue(_minDelayController.text) ?? 0,
      maxDelay: _intValue(_maxDelayController.text) ?? 0,
      maxLossPercent: _intValue(_maxLossController.text) ?? 0,
    );
  }

  CfScanParams _buildScanParams(List<String> ranges) {
    return CfScanParams(
      ranges: ranges,
      port: _portController.text.trim(),
      sampleCount: _sampleCount(),
      concurrency: 128,
      testCount: 2,
      timeout: 1500,
      // The page filters the answers the Core returns, so a bound can move
      // without a rescan; the Core reports every address it measured.
      minDelay: 0,
      maxDelay: 0,
      maxLossRate: 0,
    );
  }

  List<String> _candidateDomains({List<String>? profileDomains}) {
    profileDomains ??= ref.read(cfProfileDomainsProvider).value ?? const [];
    return {...profileDomains, ..._manualDomains}.toList()..sort();
  }

  List<String> _ranges() {
    return effectiveCfRanges(ref.read(appSettingProvider).cfRangesV4);
  }

  void _scan() {
    final port = _intValue(_portController.text);
    setState(() {
      _portInvalid = port == null || port < 1 || port > 65535;
      _sampleCountInvalid = !_sampleCountValid;
    });
    if (_portInvalid || _sampleCountInvalid) {
      return;
    }
    ref.read(cfOptimizeProvider.notifier).scan(_buildScanParams(_ranges()));
  }

  void _updateRanges() {
    ref.read(cfOptimizeProvider.notifier).updateRanges();
  }

  void _detect() {
    ref
        .read(cfOptimizeProvider.notifier)
        .detect(_candidateDomains(), _ranges());
  }

  void _toggleDomain(String domain) {
    setState(() {
      if (_selectedDomains.contains(domain)) {
        _selectedDomains.remove(domain);
      } else {
        _selectedDomains.add(domain);
      }
    });
  }

  void _addManualDomain() {
    final domain = _domainController.text.trim().toLowerCase();
    if (domain.isEmpty || domain.contains(RegExp(r'\s'))) {
      return;
    }
    setState(() {
      _manualDomains.add(domain);
      _selectedDomains.add(domain);
      _domainController.clear();
    });
  }

  Future<void> _applyTop() async {
    final appLocalizations = context.appLocalizations;
    final optimize = ref.read(cfOptimizeProvider);
    final result = optimize.scanResult;
    if (result == null || result.results.isEmpty) {
      await dialogs.showAlert(
        message: TextSpan(text: appLocalizations.cfScanFirst),
      );
      return;
    }
    // A domain that left the profile keeps its selection, and a hosts entry for
    // it would be one this page can no longer list or clear.
    final selected = _candidateDomains()
        .where(_selectedDomains.contains)
        .toSet();
    if (selected.isEmpty) {
      await dialogs.showAlert(
        message: TextSpan(text: appLocalizations.cfSelectDomainFirst),
      );
      return;
    }
    final items = _filteredItems(result.results);
    if (items.isEmpty) {
      await dialogs.showAlert(
        message: TextSpan(text: appLocalizations.cfNoResult),
      );
      return;
    }
    final outside = cfDomainsOutsideRanges(selected, optimize.detectResults);
    final undetected = outside.isEmpty
        ? cfDomainsNotDetected(selected, optimize.detectResults)
        : const <String>[];
    if (outside.isNotEmpty || undetected.isNotEmpty) {
      final warning = outside.isNotEmpty
          ? appLocalizations.cfOutsideRangesTip(outside.join(', '))
          : appLocalizations.cfUndetectedTip(undetected.join(', '));
      final confirmed = await dialogs.showMessage(
        message: TextSpan(text: warning),
        destructive: true,
        confirmText: appLocalizations.applyNow,
      );
      if (confirmed != true || !mounted) {
        return;
      }
    }
    final entries = buildCfHostEntries(selected, items);
    ref
        .read(patchClashConfigProvider.notifier)
        .update(
          (config) => config.copyWith(hosts: {...config.hosts, ...entries}),
        );
  }

  void _removeHost(String domain) {
    ref.read(patchClashConfigProvider.notifier).update((config) {
      final hosts = Map.of(config.hosts)..remove(domain);
      return config.copyWith(hosts: hosts);
    });
  }

  Future<void> _clearHosts(Set<String> domains) async {
    final appLocalizations = context.appLocalizations;
    final res = await dialogs.showMessage(
      message: TextSpan(text: appLocalizations.cfClearAllTip(domains.length)),
      destructive: true,
      confirmText: appLocalizations.cfClearAll,
    );
    if (res != true || !mounted) {
      return;
    }
    ref.read(patchClashConfigProvider.notifier).update((config) {
      final hosts = Map.of(config.hosts)
        ..removeWhere((key, _) => domains.contains(key));
      return config.copyWith(hosts: hosts);
    });
  }

  @override
  Widget build(BuildContext context) {
    final appLocalizations = context.appLocalizations;
    final state = ref.watch(cfOptimizeProvider);
    final hosts = ref.watch(
      patchClashConfigProvider.select((config) => config.hosts),
    );
    final profileDomains =
        ref.watch(cfProfileDomainsProvider).value ?? const <String>[];
    final domains = _candidateDomains(profileDomains: profileDomains);
    // This page lists and clears the mappings of its own candidate domains
    // only; a hosts entry written in the general settings for some other
    // domain is not its to touch.
    final managedHosts = {
      for (final entry in hosts.entries)
        if (domains.contains(entry.key)) entry.key: entry.value,
    };
    final scanResult = state.scanResult;
    final rangesFetchedAt = ref.watch(
      appSettingProvider.select((setting) => setting.cfRangesFetchedAt),
    );
    final ranges = effectiveCfRanges(
      ref.watch(appSettingProvider.select((setting) => setting.cfRangesV4)),
    );
    final rangesFooter = switch ((state.updatingRanges, rangesFetchedAt)) {
      (true, _) => appLocalizations.cfRangesUpdating,
      (false, 0) => appLocalizations.cfRangesBuiltIn,
      _ => appLocalizations.cfRangesUpdatedAt(
        DateTime.fromMillisecondsSinceEpoch(
          rangesFetchedAt,
        ).getLastUpdateTimeDesc(context, compact: true),
      ),
    };

    final items = [
      generateSection(
        title: appLocalizations.cfHowItWorks,
        items: [
          ListItem(
            leading: const GlyphIcon(AppGlyphs.info),
            title: Text(appLocalizations.cfOptimizeDesc),
          ),
        ],
      ),
      generateSection(
        title: appLocalizations.cfRanges,
        items: [
          ListItem(
            title: Text(appLocalizations.cfRangesCount(ranges.length)),
            subtitle: state.rangesError == null
                ? null
                : Text(
                    state.rangesError!,
                    style: TextStyle(color: context.colorScheme.error),
                  ),
          ),
        ],
        actions: [
          IconButtonData(
            glyph: AppGlyphs.sync,
            tooltip: appLocalizations.cfRangesUpdate,
            onPressed: state.scanning || state.updatingRanges
                ? null
                : _updateRanges,
          ),
        ],
        footer: rangesFooter,
      ),
      generateSection(
        title: appLocalizations.cfScanSettings,
        items: [
          FormRow(
            title: appLocalizations.port,
            invalid: _portInvalid,
            trailing: FormRowTextField(
              controller: _portController,
              keyboardType: TextInputType.number,
            ),
          ),
          FormRow(
            title: appLocalizations.cfSampleCount,
            invalid: _sampleCountInvalid,
            trailing: FormRowTextField(
              controller: _sampleCountController,
              keyboardType: TextInputType.number,
            ),
          ),
          ListItem(
            title: Text(
              state.scanning
                  ? appLocalizations.cfScanning
                  : appLocalizations.cfStartScan,
            ),
            subtitle: state.error == null
                ? null
                : Text(
                    state.error!,
                    style: TextStyle(color: context.colorScheme.error),
                  ),
            trailing: ElasticButton(
              child: FilledButton(
                onPressed: state.scanning ? null : _scan,
                child: Text(appLocalizations.cfStartScan),
              ),
            ),
            onTap: state.scanning ? null : _scan,
          ),
        ],
      ),
      if (scanResult != null)
        generateSection(
          title: appLocalizations.cfFilter,
          items: [
            FormRow(
              title: appLocalizations.cfMinDelay,
              trailing: FormRowTextField(
                controller: _minDelayController,
                keyboardType: TextInputType.number,
              ),
            ),
            FormRow(
              title: appLocalizations.cfMaxDelay,
              trailing: FormRowTextField(
                controller: _maxDelayController,
                keyboardType: TextInputType.number,
              ),
            ),
            FormRow(
              title: appLocalizations.cfMaxLoss,
              trailing: FormRowTextField(
                controller: _maxLossController,
                keyboardType: TextInputType.number,
              ),
            ),
          ],
          footer: appLocalizations.cfFilterDesc,
        ),
      if (scanResult != null)
        ListenableBuilder(
          listenable: _filterRevision,
          builder: (context, _) {
            final filtered = _filteredItems(scanResult.results);
            return generateSection(
              title: appLocalizations.cfScanResult,
              items: [
                for (final item in filtered.take(10))
                  ListItem(
                    leading: const GlyphIcon(AppGlyphs.bolt),
                    title: Text(item.ip),
                    subtitle: Text(
                      '${item.delayMs} ms · '
                      '${(item.lossRate * 100).toStringAsFixed(1)}%',
                    ),
                  ),
                if (filtered.isEmpty)
                  ListItem(title: Text(appLocalizations.cfNoResult)),
                ListItem(
                  title: Text(appLocalizations.applyNow),
                  onTap: state.scanning ? null : _applyTop,
                  trailing: const GlyphIcon(AppGlyphs.chevronForward),
                ),
              ],
              footer:
                  '${appLocalizations.cfScanSampled(scanResult.sampled)} · '
                  '${appLocalizations.cfMatchedFilter(filtered.length)} · '
                  '${(scanResult.elapsedMs / 1000).toStringAsFixed(0)} s',
            );
          },
        ),
      generateSection(
        title: appLocalizations.cfDomains,
        items: [
          FormRow(
            title: appLocalizations.cfAddDomain,
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              spacing: 8,
              children: [
                SizedBox(
                  width: 168,
                  child: FormRowTextField(
                    controller: _domainController,
                    hintText: 'cdn.example.com',
                  ),
                ),
                EntryButton.add(onPressed: _addManualDomain),
              ],
            ),
          ),
          for (final domain in domains)
            ListItem(
              leading: GlyphIcon(
                AppGlyphs.checkCircle,
                fill: _selectedDomains.contains(domain) ? 1 : 0,
              ),
              title: Text(domain),
              subtitle: () {
                final item = state.detectResults[domain];
                if (item == null) {
                  return null;
                }
                if (item.error != null) {
                  return Text(appLocalizations.cfDetectFailed);
                }
                final label = item.inRanges
                    ? appLocalizations.cfInRanges
                    : appLocalizations.cfNotInRanges;
                // The resolved addresses come from the same lookup a node's
                // dial makes, so the row shows what that dial would reach.
                final ips = item.ips.take(2).join(', ');
                return Text(ips.isEmpty ? label : '$label · $ips');
              }(),
              onTap: () => _toggleDomain(domain),
            ),
        ],
        actions: [
          IconButtonData(
            glyph: AppGlyphs.dns,
            tooltip: appLocalizations.cfDetect,
            onPressed: state.detecting ? null : _detect,
          ),
        ],
        footer: state.detecting ? appLocalizations.cfDetecting : null,
      ),
      generateSection(
        title: appLocalizations.cfAppliedHosts,
        items: [
          for (final entry in managedHosts.entries)
            ListItem(
              title: Text(entry.key),
              subtitle: Text(entry.value),
              trailing: EntryButton.remove(
                onPressed: () => _removeHost(entry.key),
              ),
            ),
        ],
        actions: [
          IconButtonData(
            glyph: AppGlyphs.clearAll,
            tooltip: appLocalizations.cfClearAll,
            onPressed: managedHosts.isEmpty
                ? null
                : () => _clearHosts(managedHosts.keys.toSet()),
          ),
        ],
        footer: appLocalizations.cfAppliedHint,
      ),
    ];

    return Scaffold(
      title: appLocalizations.cfOptimize,
      body: Builder(
        builder: (context) => PrismListView(
          itemCount: items.length,
          itemBuilder: (_, index) => items[index],
          padding: EdgeInsets.only(
            left: 16,
            right: 16,
            top: context.sectionsTopPadding,
            bottom: 20 + context.bottomInset,
          ),
        ),
      ),
    );
  }
}
