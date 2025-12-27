import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/subscription.dart';
import '../services/api_service.dart';
import 'auth_provider.dart';

final subscriptionsProvider = StateNotifierProvider<SubscriptionsNotifier, AsyncValue<List<Subscription>>>((ref) {
  final apiService = ref.watch(apiServiceProvider);
  return SubscriptionsNotifier(apiService);
});

class SubscriptionsNotifier extends StateNotifier<AsyncValue<List<Subscription>>> {
  final ApiService _apiService;

  SubscriptionsNotifier(this._apiService) : super(const AsyncValue.loading()) {
    loadSubscriptions();
  }

  Future<void> loadSubscriptions() async {
    state = const AsyncValue.loading();
    try {
      final subscriptions = await _apiService.getSubscriptions();
      state = AsyncValue.data(subscriptions);
    } catch (e, stack) {
      state = AsyncValue.error(e, stack);
    }
  }

  Future<void> addSubscription(Map<String, dynamic> data) async {
    try {
      await _apiService.createSubscription(data);
      await loadSubscriptions();
    } catch (e) {
      rethrow;
    }
  }

  Future<void> importSubscription(String url) async {
    try {
      await _apiService.importSubscription(url);
      await loadSubscriptions();
    } catch (e) {
      rethrow;
    }
  }

  Future<void> deleteSubscription(String id) async {
    try {
      await _apiService.deleteSubscription(id);
      await loadSubscriptions();
    } catch (e) {
      rethrow;
    }
  }

  Future<void> refresh() async {
    await loadSubscriptions();
  }
}
