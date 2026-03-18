/**
 * P2P Lambda API Client
 * Base URL: https://api.lambda.p2p.org
 * Auth: Authorization header (raw key, no Bearer prefix)
 */

const BASE_URL = 'https://api.lambda.p2p.org';

export class P2PLambdaClient {
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  private async request<T>(
    method: string,
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined>,
    body?: any
  ): Promise<T> {
    const url = new URL(`${BASE_URL}${endpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const options: RequestInit = {
      method,
      headers: {
        'Authorization': this.apiKey,
        'Accept': 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    };

    const response = await fetch(url.toString(), options);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`API Error ${response.status}: ${text}`);
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  // === Chains ===

  async listChains(limit: number, pageToken?: string) {
    return this.request<any>('GET', '/api/v1/chains', { limit, page_token: pageToken });
  }

  async getChain(chainId: string) {
    return this.request<any>('GET', `/api/v1/chains/${encodeURIComponent(chainId)}`);
  }

  // === Tokens ===

  async listTokens(limit: number, chainId?: string, pageToken?: string) {
    return this.request<any>('GET', '/api/v1/tokens', { limit, chain_id: chainId, page_token: pageToken });
  }

  async getToken(tokenId: string) {
    return this.request<any>('GET', `/api/v1/tokens/${encodeURIComponent(tokenId)}`);
  }

  async getSupportedPriceSymbols() {
    return this.request<any>('GET', '/api/v1/tokens/prices/supported');
  }

  async searchPrices(symbols: string[], timestamps: number[]) {
    return this.request<any>('POST', '/api/v1/tokens/prices/search', undefined, { symbols, timestamps });
  }

  // === Wallet Portfolio ===

  async getWalletBalances(
    address: string,
    chainId?: string,
    assetType?: string,
    assetsIds?: string[],
    includeZeroPriceTokens?: boolean,
    includeMetaTokens?: boolean
  ) {
    const params: Record<string, string | number | boolean | undefined> = {
      chain_id: chainId,
      asset_type: assetType,
      include_zero_price_tokens: includeZeroPriceTokens,
      include_meta_tokens: includeMetaTokens,
    };
    if (assetsIds?.length) {
      params.assets_ids = assetsIds.join(',');
    }
    return this.request<any>('GET', `/api/v2/wallets/${encodeURIComponent(address)}/balances`, params);
  }

  async getWalletNetWorth(address: string, chainId?: string, period?: string) {
    return this.request<any>('GET', `/api/v1/wallets/${encodeURIComponent(address)}/tokens-net-worth`, {
      chain_id: chainId,
      period,
    });
  }

  async getNonEvmBalances(chain: string, address: string, assetType?: string, includeZeroPriceTokens?: boolean) {
    return this.request<any>(
      'GET',
      `/api/v1/chains/${encodeURIComponent(chain)}/wallets/${encodeURIComponent(address)}/balances`,
      { asset_type: assetType, include_zero_price_tokens: includeZeroPriceTokens }
    );
  }

  // === PnL ===

  async getPositionPnl(
    address: string,
    chainId: string,
    category: string,
    positionId: string,
    startTimestamp?: number,
    endTimestamp?: number,
    granularity?: string,
    pointsLimit?: number
  ) {
    return this.request<any>(
      'GET',
      `/api/v1/wallets/${encodeURIComponent(address)}/chains/${encodeURIComponent(chainId)}/pnl-history`,
      {
        category,
        position_id: positionId,
        start_timestamp: startTimestamp,
        end_timestamp: endTimestamp,
        granularity,
        points_limit: pointsLimit,
      }
    );
  }

  async getSwapsPnl(
    address: string,
    chainId: string,
    startTimestamp?: number,
    endTimestamp?: number,
    protocolNames?: string[]
  ) {
    return this.request<any>(
      'POST',
      `/api/v1/wallets/${encodeURIComponent(address)}/chains/${encodeURIComponent(chainId)}/swaps-pnl`,
      undefined,
      {
        start_timestamp: startTimestamp,
        end_timestamp: endTimestamp,
        protocol_names: protocolNames,
      }
    );
  }

  async getWalletPnlHistory(
    chainId: string,
    addresses: string[],
    startTimestamp?: number,
    endTimestamp?: number,
    granularity?: string,
    pointsLimit?: number
  ) {
    return this.request<any>(
      'POST',
      `/api/v1/chains/${encodeURIComponent(chainId)}/wallet-pnl-history`,
      undefined,
      {
        addresses,
        start_timestamp: startTimestamp,
        end_timestamp: endTimestamp,
        granularity,
        points_limit: pointsLimit,
      }
    );
  }

  async getAggregatedPnl(
    chainId: string,
    positions: { address: string; category: string; position_id: string }[],
    startTimestamp?: number,
    endTimestamp?: number,
    granularity?: string,
    pointsLimit?: number
  ) {
    return this.request<any>(
      'POST',
      `/api/v1/chains/${encodeURIComponent(chainId)}/aggregated-pnl-history`,
      undefined,
      {
        positions,
        start_timestamp: startTimestamp,
        end_timestamp: endTimestamp,
        granularity,
        points_limit: pointsLimit,
      }
    );
  }

  // === Transactions ===

  async getTransactionHistory(
    address: string,
    chainIds?: string[],
    start?: number,
    end?: number,
    limit?: number,
    pageToken?: string
  ) {
    const params: Record<string, string | number | boolean | undefined> = {
      start,
      end,
      limit,
      page_token: pageToken,
    };
    if (chainIds?.length) {
      params.chain_ids = chainIds.join(',');
    }
    return this.request<any>('GET', `/api/v1/transactions/${encodeURIComponent(address)}/history`, params);
  }

  // === NFTs ===

  async getWalletNfts(
    address: string,
    limit: number,
    chainIds?: string[],
    collectionIds?: string[],
    withMetaData?: boolean,
    refreshCache?: boolean,
    pageToken?: string
  ) {
    const params: Record<string, string | number | boolean | undefined> = {
      limit,
      with_meta_data: withMetaData,
      refresh_cache: refreshCache,
      page_token: pageToken,
    };
    if (chainIds?.length) {
      params.chain_ids = chainIds.join(',');
    }
    if (collectionIds?.length) {
      params.collection_ids = collectionIds.join(',');
    }
    return this.request<any>('GET', `/api/v1/wallets/${encodeURIComponent(address)}/nfts`, params);
  }

  async getWalletNftCollections(address: string, chainIds?: string[]) {
    const params: Record<string, string | number | boolean | undefined> = {};
    if (chainIds?.length) {
      params.chain_ids = chainIds.join(',');
    }
    return this.request<any>('GET', `/api/v1/wallets/${encodeURIComponent(address)}/nft-collections`, params);
  }

  async getNft(chainId: string, contractAddress: string, nftId: string) {
    return this.request<any>(
      'GET',
      `/api/v1/chains/${encodeURIComponent(chainId)}/contract-address/${encodeURIComponent(contractAddress)}/nfts/${encodeURIComponent(nftId)}`
    );
  }

  async refreshNft(chainId: string, contractAddress: string, nftId: string) {
    return this.request<any>(
      'POST',
      `/api/v1/chains/${encodeURIComponent(chainId)}/contract-address/${encodeURIComponent(contractAddress)}/nfts/${encodeURIComponent(nftId)}/refresh`
    );
  }

  async getNonEvmNfts(chain: string, address: string) {
    return this.request<any>(
      'GET',
      `/api/v1/chains/${encodeURIComponent(chain)}/wallets/${encodeURIComponent(address)}/nfts`
    );
  }

  // === Yield Recommendations ===

  async getYieldRecommendations(address: string, body?: any) {
    return this.request<any>(
      'POST',
      `/api/v1/wallets/${encodeURIComponent(address)}/recommendations`,
      undefined,
      body || {}
    );
  }

  // === APR History ===

  async getAprHistory(
    requests: { chain: string; protocol: string; pool_id: string; asset: string; start_date: string; end_date: string }[]
  ) {
    return this.request<any>('POST', '/api/v1/protocols/apr/history', undefined, { requests });
  }
}
