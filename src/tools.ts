import { z } from 'zod';
import { P2PLambdaClient } from './api-client.js';

interface ToolDef {
  name: string;
  description: string;
  inputSchema: z.ZodType<any>;
  handler: (client: P2PLambdaClient, args: any) => Promise<any>;
}

// Reusable schemas
const paginationParams = {
  limit: z.number().max(100).describe('Max items to return (max 100)'),
  page_token: z.string().optional().describe('Pagination token for next page'),
};

const pnlTimeParams = {
  start_timestamp: z.number().optional().describe('Start time in milliseconds'),
  end_timestamp: z.number().optional().describe('End time in milliseconds'),
  granularity: z.enum(['month', 'week', 'day', 'hour', 'five_minutes', 'any']).optional().describe('Data granularity'),
  points_limit: z.number().max(100).optional().describe('Max data points (max 100)'),
};

const evmChainId = z.enum([
  'ethereum', 'xdai', 'base', 'arbitrum', 'polygon', 'optimism', 'binance-smart-chain', 'solana',
]).describe('Blockchain network ID');

export const tools: ToolDef[] = [
  // === Chains ===
  {
    name: 'chains_list',
    description: 'List all supported blockchain networks',
    inputSchema: z.object({
      ...paginationParams,
    }),
    handler: async (client, args) => client.listChains(args.limit, args.page_token),
  },
  {
    name: 'chains_get',
    description: 'Get details for a specific chain',
    inputSchema: z.object({
      chain_id: z.string().describe('Chain identifier (e.g. ethereum, solana)'),
    }),
    handler: async (client, args) => client.getChain(args.chain_id),
  },

  // === Tokens ===
  {
    name: 'tokens_list',
    description: 'List supported tokens across chains',
    inputSchema: z.object({
      ...paginationParams,
      chain_id: z.string().optional().describe('Filter by chain ID'),
    }),
    handler: async (client, args) => client.listTokens(args.limit, args.chain_id, args.page_token),
  },
  {
    name: 'tokens_get',
    description: 'Get token info by ID',
    inputSchema: z.object({
      token_id: z.string().describe('Token UUID'),
    }),
    handler: async (client, args) => client.getToken(args.token_id),
  },
  {
    name: 'tokens_prices_supported',
    description: 'List token symbols with price data',
    inputSchema: z.object({}),
    handler: async (client) => client.getSupportedPriceSymbols(),
  },
  {
    name: 'tokens_prices_search',
    description: 'Get historical prices for tokens',
    inputSchema: z.object({
      symbols: z.array(z.string()).describe('Token symbols (e.g. ["ETH", "BTC"])'),
      timestamps: z.array(z.number()).describe('Unix timestamps in seconds or ms'),
    }),
    handler: async (client, args) => client.searchPrices(args.symbols, args.timestamps),
  },

  // === Wallet Portfolio ===
  {
    name: 'wallet_balances',
    description: 'Get wallet token and DeFi balances',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_id: z.string().optional().describe('Filter by chain'),
      asset_type: z.enum(['TOKEN', 'DEFI', 'ALL']).optional().describe('Asset type filter'),
      assets_ids: z.array(z.string()).optional().describe('Filter by specific asset IDs'),
      include_zero_price_tokens: z.boolean().optional().describe('Include zero-price tokens'),
      include_meta_tokens: z.boolean().optional().describe('Include meta tokens'),
    }),
    handler: async (client, args) =>
      client.getWalletBalances(
        args.address, args.chain_id, args.asset_type,
        args.assets_ids, args.include_zero_price_tokens, args.include_meta_tokens
      ),
  },
  {
    name: 'wallet_net_worth',
    description: 'Get historical wallet net worth over time',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_id: z.string().optional().describe('Filter by chain'),
      period: z.enum(['HOUR', 'DAY', 'WEEK', 'MONTH', 'YEAR', 'FULL']).optional().describe('Time period'),
    }),
    handler: async (client, args) => client.getWalletNetWorth(args.address, args.chain_id, args.period),
  },
  {
    name: 'wallet_balances_non_evm',
    description: 'Get non-EVM wallet balances (Solana/Bitcoin)',
    inputSchema: z.object({
      chain: z.enum(['solana', 'bitcoin']).describe('Non-EVM chain'),
      address: z.string().describe('Wallet address'),
      asset_type: z.enum(['TOKEN', 'DEFI', 'ALL']).optional().describe('Asset type filter'),
      include_zero_price_tokens: z.boolean().optional().describe('Include zero-price tokens'),
    }),
    handler: async (client, args) =>
      client.getNonEvmBalances(args.chain, args.address, args.asset_type, args.include_zero_price_tokens),
  },

  // === PnL ===
  {
    name: 'pnl_position',
    description: 'Get PnL for a single DeFi position',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_id: evmChainId,
      category: z.string().describe('Position category (erc20, aave-v3-supply, uni-v3-supply, lido, etc.)'),
      position_id: z.string().describe('Position address or encoded ID'),
      ...pnlTimeParams,
    }),
    handler: async (client, args) =>
      client.getPositionPnl(
        args.address, args.chain_id, args.category, args.position_id,
        args.start_timestamp, args.end_timestamp, args.granularity, args.points_limit
      ),
  },
  {
    name: 'pnl_swaps',
    description: 'Analyze swap transaction PnL',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_id: z.enum(['ethereum', 'arbitrum', 'polygon', 'optimism', 'base', 'zksync-era']).describe('Chain'),
      start_timestamp: z.number().optional().describe('Start time in ms'),
      end_timestamp: z.number().optional().describe('End time in ms'),
      protocol_names: z.array(z.enum(['sushi-v2', 'sushi-v3', 'sushi-swap-aggregator'])).optional().describe('Filter by protocol'),
    }),
    handler: async (client, args) =>
      client.getSwapsPnl(args.address, args.chain_id, args.start_timestamp, args.end_timestamp, args.protocol_names),
  },
  {
    name: 'pnl_wallet',
    description: 'Get aggregated PnL for entire wallets',
    inputSchema: z.object({
      chain_id: z.string().describe('Chain ID'),
      addresses: z.array(z.string()).describe('Wallet addresses'),
      ...pnlTimeParams,
    }),
    handler: async (client, args) =>
      client.getWalletPnlHistory(
        args.chain_id, args.addresses,
        args.start_timestamp, args.end_timestamp, args.granularity, args.points_limit
      ),
  },
  {
    name: 'pnl_aggregated',
    description: 'Get aggregated PnL across multiple positions',
    inputSchema: z.object({
      chain_id: z.string().describe('Chain ID'),
      positions: z.array(z.object({
        address: z.string().describe('Wallet address'),
        category: z.string().describe('Position category'),
        position_id: z.string().describe('Position ID'),
      })).describe('Positions to aggregate'),
      ...pnlTimeParams,
    }),
    handler: async (client, args) =>
      client.getAggregatedPnl(
        args.chain_id, args.positions,
        args.start_timestamp, args.end_timestamp, args.granularity, args.points_limit
      ),
  },

  // === Transactions ===
  {
    name: 'transactions_history',
    description: 'Get transaction history for a wallet',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_ids: z.array(z.string()).optional().describe('Filter by chain IDs'),
      start: z.number().optional().describe('Start timestamp'),
      end: z.number().optional().describe('End timestamp'),
      limit: z.number().max(100).optional().describe('Max results (default 100)'),
      page_token: z.string().optional().describe('Pagination token'),
    }),
    handler: async (client, args) =>
      client.getTransactionHistory(args.address, args.chain_ids, args.start, args.end, args.limit, args.page_token),
  },

  // === NFTs ===
  {
    name: 'nfts_list',
    description: 'Get NFTs owned by a wallet',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      limit: z.number().max(100).describe('Max results'),
      chain_ids: z.array(z.string()).optional().describe('Filter by chains'),
      collection_ids: z.array(z.string()).optional().describe('Filter by collections'),
      with_meta_data: z.boolean().optional().describe('Include NFT metadata'),
      refresh_cache: z.boolean().optional().describe('Force cache refresh'),
      page_token: z.string().optional().describe('Pagination token'),
    }),
    handler: async (client, args) =>
      client.getWalletNfts(
        args.address, args.limit, args.chain_ids, args.collection_ids,
        args.with_meta_data, args.refresh_cache, args.page_token
      ),
  },
  {
    name: 'nft_collections',
    description: 'Get NFT collections for a wallet',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
      chain_ids: z.array(z.string()).optional().describe('Filter by chains'),
    }),
    handler: async (client, args) => client.getWalletNftCollections(args.address, args.chain_ids),
  },
  {
    name: 'nft_get',
    description: 'Get a specific NFT by chain/contract/ID',
    inputSchema: z.object({
      chain_id: z.string().describe('Chain ID (e.g. ethereum, base)'),
      contract_address: z.string().describe('NFT contract address'),
      nft_id: z.string().describe('NFT token ID'),
    }),
    handler: async (client, args) => client.getNft(args.chain_id, args.contract_address, args.nft_id),
  },
  {
    name: 'nft_refresh',
    description: 'Refresh NFT metadata cache',
    inputSchema: z.object({
      chain_id: z.string().describe('Chain ID'),
      contract_address: z.string().describe('NFT contract address'),
      nft_id: z.string().describe('NFT token ID'),
    }),
    handler: async (client, args) => client.refreshNft(args.chain_id, args.contract_address, args.nft_id),
  },
  {
    name: 'nfts_non_evm',
    description: 'Get NFTs on non-EVM chains (Solana)',
    inputSchema: z.object({
      chain: z.enum(['solana']).describe('Non-EVM chain'),
      address: z.string().describe('Wallet address'),
    }),
    handler: async (client, args) => client.getNonEvmNfts(args.chain, args.address),
  },

  // === Yield & APR ===
  {
    name: 'yield_recommendations',
    description: 'Get personalized yield opportunities',
    inputSchema: z.object({
      address: z.string().describe('Wallet address'),
    }),
    handler: async (client, args) => client.getYieldRecommendations(args.address),
  },
  {
    name: 'apr_history',
    description: 'Get APR history for DeFi protocols',
    inputSchema: z.object({
      requests: z.array(z.object({
        chain: z.string().describe('Chain name'),
        protocol: z.enum([
          'aave_v3', 'aura_finance', 'compound_v3', 'ethena', 'euler', 'fluid',
          'gearbox', 'morpho', 'pendle_v2', 'spark', 'lido', 'etherfi',
          'kinetiq', 'hyperlend', 'yearn_v3', 'valantis', 'yieldnest', 'maple',
        ]).describe('Protocol name'),
        pool_id: z.string().describe('Pool identifier'),
        asset: z.string().describe('Asset symbol'),
        start_date: z.string().describe('Start date (YYYY-MM-DD)'),
        end_date: z.string().describe('End date (YYYY-MM-DD)'),
      })).describe('APR query requests'),
    }),
    handler: async (client, args) => client.getAprHistory(args.requests),
  },
];
