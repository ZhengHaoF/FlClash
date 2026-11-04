// GENERATED CODE - DO NOT MODIFY BY HAND

part of '../cf_optimize.dart';

// **************************************************************************
// RiverpodGenerator
// **************************************************************************

// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint, type=warning

@ProviderFor(CfOptimize)
final cfOptimizeProvider = CfOptimizeProvider._();

final class CfOptimizeProvider
    extends $NotifierProvider<CfOptimize, CfOptimizeState> {
  CfOptimizeProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'cfOptimizeProvider',
        isAutoDispose: false,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$cfOptimizeHash();

  @$internal
  @override
  CfOptimize create() => CfOptimize();

  /// {@macro riverpod.override_with_value}
  Override overrideWithValue(CfOptimizeState value) {
    return $ProviderOverride(
      origin: this,
      providerOverride: $SyncValueProvider<CfOptimizeState>(value),
    );
  }
}

String _$cfOptimizeHash() => r'5d9e7a3d38ccab0a2271ccee7536d5853715421f';

abstract class _$CfOptimize extends $Notifier<CfOptimizeState> {
  CfOptimizeState build();
  @$mustCallSuper
  @override
  WhenComplete runBuild() {
    final ref = this.ref as $Ref<CfOptimizeState, CfOptimizeState>;
    final element =
        ref.element
            as $ClassProviderElement<
              AnyNotifier<CfOptimizeState, CfOptimizeState>,
              CfOptimizeState,
              Object?,
              Object?
            >;
    return element.handleCreate(ref, build);
  }
}

/// The server domains the current profile's own proxies dial, read out of the
/// raw subscription file in an isolate. A provider's contents stay external,
/// and a proxy already dialing an IP literal has no domain to optimize.

@ProviderFor(cfProfileDomains)
final cfProfileDomainsProvider = CfProfileDomainsProvider._();

/// The server domains the current profile's own proxies dial, read out of the
/// raw subscription file in an isolate. A provider's contents stay external,
/// and a proxy already dialing an IP literal has no domain to optimize.

final class CfProfileDomainsProvider
    extends
        $FunctionalProvider<
          AsyncValue<List<String>>,
          List<String>,
          FutureOr<List<String>>
        >
    with $FutureModifier<List<String>>, $FutureProvider<List<String>> {
  /// The server domains the current profile's own proxies dial, read out of the
  /// raw subscription file in an isolate. A provider's contents stay external,
  /// and a proxy already dialing an IP literal has no domain to optimize.
  CfProfileDomainsProvider._()
    : super(
        from: null,
        argument: null,
        retry: null,
        name: r'cfProfileDomainsProvider',
        isAutoDispose: true,
        dependencies: null,
        $allTransitiveDependencies: null,
      );

  @override
  String debugGetCreateSourceHash() => _$cfProfileDomainsHash();

  @$internal
  @override
  $FutureProviderElement<List<String>> $createElement(
    $ProviderPointer pointer,
  ) => $FutureProviderElement(pointer);

  @override
  FutureOr<List<String>> create(Ref ref) {
    return cfProfileDomains(ref);
  }
}

String _$cfProfileDomainsHash() => r'4d95fb8f6a72b8b71d249456f00d595625e43f0f';
