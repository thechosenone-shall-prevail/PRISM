-- ============================================================================
-- APTrace — Supabase Database Schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. APT Group Profiles
-- ============================================================================
CREATE TABLE IF NOT EXISTS apt_groups (
  id TEXT PRIMARY KEY,                    -- MITRE ID e.g. "G0032"
  name TEXT UNIQUE NOT NULL,              -- "Lazarus Group"
  aliases TEXT[] NOT NULL DEFAULT '{}',
  nation TEXT NOT NULL,
  nation_code TEXT,
  flag TEXT,
  motivation TEXT[] NOT NULL DEFAULT '{}',
  target_sectors TEXT[] NOT NULL DEFAULT '{}',
  target_regions TEXT[] NOT NULL DEFAULT '{}',
  active_since INT,
  last_seen INT,
  description TEXT,
  known_campaigns TEXT[] NOT NULL DEFAULT '{}',
  known_tools TEXT[] NOT NULL DEFAULT '{}',
  ttps JSONB NOT NULL DEFAULT '{}',
  behavioral_dna JSONB DEFAULT '{}',
  operational_hours JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- 2. Malware Family Fingerprints
-- ============================================================================
CREATE TABLE IF NOT EXISTS malware_families (
  id SERIAL PRIMARY KEY,
  family TEXT UNIQUE NOT NULL,
  cluster TEXT NOT NULL,                  -- Links to apt_groups.name
  summary TEXT,
  geo_context TEXT,
  known_hashes TEXT[] DEFAULT '{}',
  known_hash_prefixes TEXT[] DEFAULT '{}',
  known_imphashes TEXT[] DEFAULT '{}',
  file_types TEXT[] DEFAULT '{}',
  import_keywords TEXT[] DEFAULT '{}',
  string_keywords TEXT[] DEFAULT '{}',
  behavior_keywords TEXT[] DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- 3. Attribution Analysis Results (persisted history)
-- ============================================================================
CREATE TABLE IF NOT EXISTS analyses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  analysis_type TEXT NOT NULL CHECK (analysis_type IN ('attribution', 'malware_retracing')),
  input_mode TEXT,                        -- 'analyst_text', 'log_file', 'demo', 'hash', 'file'
  input_summary TEXT,                     -- Truncated input for display
  -- Attribution results
  top_group TEXT,
  top_confidence FLOAT,
  confidence_tier TEXT,
  gate_passed BOOLEAN DEFAULT FALSE,
  observed_techniques TEXT[] DEFAULT '{}',
  context_signals TEXT[] DEFAULT '{}',
  drift_warning TEXT,
  -- ML model info
  model_version TEXT,                     -- Which model produced this result
  model_confidence FLOAT,                 -- ML model's raw confidence
  rule_confidence FLOAT,                  -- Rule engine's raw confidence (if used)
  -- Full result JSON
  full_result JSONB NOT NULL DEFAULT '{}',
  -- Analyst feedback for continuous learning
  analyst_feedback TEXT CHECK (analyst_feedback IN ('confirmed', 'corrected', 'rejected', NULL)),
  corrected_group TEXT,                   -- If corrected, what was the real group?
  feedback_notes TEXT,
  feedback_at TIMESTAMPTZ,
  artifact_path TEXT,
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_analyses_created_at ON analyses(created_at DESC);
CREATE INDEX idx_analyses_top_group ON analyses(top_group);
CREATE INDEX idx_analyses_type ON analyses(analysis_type);
CREATE INDEX idx_analyses_feedback ON analyses(analyst_feedback) WHERE analyst_feedback IS NOT NULL;

-- ============================================================================
-- 4. Intel Queue (replaces raw_queue.jsonl)
-- ============================================================================
CREATE TABLE IF NOT EXISTS intel_queue (
  id TEXT PRIMARY KEY,
  title TEXT,
  source_name TEXT,
  source_tier TEXT CHECK (source_tier IN ('official', 'vendor', 'research', 'media', 'community', 'unknown')),
  published_at TIMESTAMPTZ,
  url TEXT,
  groups TEXT[] DEFAULT '{}',
  summary TEXT,
  content TEXT,
  processed BOOLEAN DEFAULT FALSE,
  ingested_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_intel_queue_ingested ON intel_queue(ingested_at DESC);
CREATE INDEX idx_intel_queue_processed ON intel_queue(processed);

-- ============================================================================
-- 5. Emerging Clusters (replaces emerging_clusters.json)
-- ============================================================================
CREATE TABLE IF NOT EXISTS emerging_clusters (
  cluster_id TEXT PRIMARY KEY,
  status TEXT DEFAULT 'EMERGING' CHECK (status IN ('EMERGING', 'TRACKED', 'ATTRIBUTED', 'ARCHIVED')),
  techniques TEXT[] DEFAULT '{}',
  context_signals TEXT[] DEFAULT '{}',
  matched_keywords TEXT[] DEFAULT '{}',
  latest_hypotheses JSONB DEFAULT '[]',
  sightings INT DEFAULT 1,
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================================
-- 6. ML Model Registry
-- ============================================================================
CREATE TABLE IF NOT EXISTS ml_models (
  id SERIAL PRIMARY KEY,
  version TEXT UNIQUE NOT NULL,           -- e.g. "v1.0.0-20260312"
  model_type TEXT NOT NULL DEFAULT 'xgboost',
  status TEXT DEFAULT 'staged' CHECK (status IN ('staged', 'active', 'retired')),
  -- Training metadata
  training_samples_count INT,
  feature_count INT,
  class_count INT,
  -- Evaluation metrics
  accuracy FLOAT,
  macro_f1 FLOAT,
  per_class_metrics JSONB DEFAULT '{}',   -- {"Lazarus Group": {"precision": 0.9, "recall": 0.85, "f1": 0.87}}
  -- Storage
  model_path TEXT,                        -- Supabase Storage path to .pkl
  feature_schema_path TEXT,               -- Path to feature_schema.json
  -- Continuous learning
  feedback_samples_used INT DEFAULT 0,    -- How many feedback samples were in training
  drift_score FLOAT,                      -- Confidence drift metric at deployment
  -- Timestamps
  trained_at TIMESTAMPTZ DEFAULT NOW(),
  deployed_at TIMESTAMPTZ,
  retired_at TIMESTAMPTZ
);

-- ============================================================================
-- 7. Training Samples (for continuous learning)
-- ============================================================================
CREATE TABLE IF NOT EXISTS training_samples (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL CHECK (source IN ('synthetic', 'analyst_feedback', 'intel_report', 'mitre_sync')),
  label TEXT NOT NULL,                    -- APT group name (target class)
  features JSONB NOT NULL,                -- Feature vector as JSON
  -- Provenance
  source_analysis_id UUID REFERENCES analyses(id) ON DELETE SET NULL,
  source_intel_id TEXT,
  source_description TEXT,
  -- Quality
  confidence FLOAT DEFAULT 1.0,          -- Weight for training (1.0 = gold, 0.5 = synthetic)
  validated BOOLEAN DEFAULT FALSE,
  -- Time decay
  sample_date TIMESTAMPTZ DEFAULT NOW(),  -- When the attack occurred (for time-decay weighting)
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_training_samples_label ON training_samples(label);
CREATE INDEX idx_training_samples_source ON training_samples(source);
CREATE INDEX idx_training_samples_date ON training_samples(sample_date DESC);

-- ============================================================================
-- 8. Row Level Security
-- ============================================================================

-- Analyses: users can view/insert their own
ALTER TABLE analyses ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own analyses"
  ON analyses FOR SELECT
  USING (auth.uid() = user_id OR user_id IS NULL);

CREATE POLICY "Users can insert own analyses"
  ON analyses FOR INSERT
  WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

CREATE POLICY "Users can update own analyses feedback"
  ON analyses FOR UPDATE
  USING (auth.uid() = user_id OR user_id IS NULL)
  WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

-- Public read for reference tables
ALTER TABLE apt_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read apt_groups" ON apt_groups FOR SELECT USING (true);

ALTER TABLE malware_families ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read malware_families" ON malware_families FOR SELECT USING (true);

ALTER TABLE emerging_clusters ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read emerging_clusters" ON emerging_clusters FOR SELECT USING (true);

ALTER TABLE ml_models ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Public read ml_models" ON ml_models FOR SELECT USING (true);

-- Service role bypass for backend operations (FastAPI uses service role key)
-- Note: Service role key automatically bypasses RLS

-- ============================================================================
-- 9. Updated_at trigger
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER apt_groups_updated_at
  BEFORE UPDATE ON apt_groups
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER malware_families_updated_at
  BEFORE UPDATE ON malware_families
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- 10. Useful views
-- ============================================================================

-- Recent analyses summary
CREATE OR REPLACE VIEW recent_analyses AS
SELECT
  id,
  analysis_type,
  input_mode,
  input_summary,
  top_group,
  top_confidence,
  confidence_tier,
  gate_passed,
  model_version,
  analyst_feedback,
  created_at
FROM analyses
ORDER BY created_at DESC
LIMIT 100;

-- Drift monitoring: weekly average confidence
CREATE OR REPLACE VIEW drift_monitor AS
SELECT
  DATE_TRUNC('week', created_at) AS week,
  COUNT(*) AS analysis_count,
  ROUND(AVG(top_confidence)::numeric, 3) AS avg_confidence,
  ROUND(AVG(model_confidence)::numeric, 3) AS avg_model_confidence,
  COUNT(*) FILTER (WHERE analyst_feedback = 'confirmed') AS confirmed,
  COUNT(*) FILTER (WHERE analyst_feedback = 'corrected') AS corrected,
  COUNT(*) FILTER (WHERE analyst_feedback = 'rejected') AS rejected
FROM analyses
WHERE analysis_type = 'attribution'
GROUP BY DATE_TRUNC('week', created_at)
ORDER BY week DESC;

-- Training data stats
CREATE OR REPLACE VIEW training_stats AS
SELECT
  label,
  source,
  COUNT(*) AS sample_count,
  ROUND(AVG(confidence)::numeric, 3) AS avg_confidence,
  MIN(sample_date) AS earliest,
  MAX(sample_date) AS latest
FROM training_samples
GROUP BY label, source
ORDER BY label, source;
