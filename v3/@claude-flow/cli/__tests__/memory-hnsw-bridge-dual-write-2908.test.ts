/**
 * Regression coverage for #2908: a successful AgentDB bridge write must not
 * suppress the persistent local HNSW update. `hooks_post-task --store-results`
 * stores through the canonical memory path, and semantic routing reads the
 * `.swarm/hnsw.index` + `.swarm/hnsw.metadata.json` pair. Both indexes must
 * therefore be updated by the same write.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const state = vi.hoisted(() => ({
  bridgeAddToHNSW: vi.fn(async () => true),
  localInserts: [] as Array<{ id: string; vector: Float32Array }>,
}));

vi.mock('../src/memory/memory-bridge.js', () => ({
  bridgeAddToHNSW: state.bridgeAddToHNSW,
}));

vi.mock('@ruvector/core', () => {
  class VectorDb {
    async len(): Promise<number> {
      return 0;
    }

    async insert(input: { id: string; vector: Float32Array }): Promise<void> {
      state.localInserts.push(input);
    }

    async search(): Promise<never[]> {
      return [];
    }
  }

  return {
    VectorDb,
    default: { VectorDb },
  };
});

let root: string;
const originalRoot = process.env.CLAUDE_FLOW_MEMORY_PATH;
const originalDisableBridge = process.env.CLAUDE_FLOW_DISABLE_BRIDGE;

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), 'ruflo-memory-2908-'));
  process.env.CLAUDE_FLOW_MEMORY_PATH = root;
  delete process.env.CLAUDE_FLOW_DISABLE_BRIDGE;
  state.bridgeAddToHNSW.mockClear();
  state.localInserts.length = 0;
  vi.resetModules();
});

afterEach(() => {
  vi.resetModules();
  if (originalRoot === undefined) delete process.env.CLAUDE_FLOW_MEMORY_PATH;
  else process.env.CLAUDE_FLOW_MEMORY_PATH = originalRoot;
  if (originalDisableBridge === undefined) delete process.env.CLAUDE_FLOW_DISABLE_BRIDGE;
  else process.env.CLAUDE_FLOW_DISABLE_BRIDGE = originalDisableBridge;
  rmSync(root, { recursive: true, force: true });
});

describe('persistent HNSW dual-write (#2908)', () => {
  it('updates the local HNSW index even when the AgentDB bridge succeeds', async () => {
    const memory = await import('../src/memory/memory-initializer.js');
    const id = 'post-task-2908';
    const embedding = [0.2, 0.4, 0.8];

    const indexed = await memory.addToHNSWIndex(id, embedding, {
      id,
      key: 'routing-decision:task-2908',
      namespace: 'patterns',
      content: 'quenzibar regression marker',
    });

    expect(indexed).toBe(true);
    expect(state.bridgeAddToHNSW).toHaveBeenCalledTimes(1);
    expect(state.bridgeAddToHNSW).toHaveBeenCalledWith(
      id,
      embedding,
      expect.objectContaining({
        key: 'routing-decision:task-2908',
        namespace: 'patterns',
      }),
    );

    expect(state.localInserts).toHaveLength(1);
    expect(state.localInserts[0]?.id).toBe(id);

    const metadataPath = path.join(root, 'hnsw.metadata.json');
    expect(existsSync(metadataPath)).toBe(true);
    const metadata = new Map<string, { key: string; namespace: string }>(
      JSON.parse(readFileSync(metadataPath, 'utf8')),
    );
    expect(metadata.get(id)).toMatchObject({
      key: 'routing-decision:task-2908',
      namespace: 'patterns',
    });
  });
});
