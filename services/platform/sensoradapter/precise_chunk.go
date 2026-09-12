package sensoradapter

type PreciseChunkProcessor = chunkProcessor[PreciseRuntimeEvent]

func NewPreciseChunkProcessor(config ChunkProcessorConfig) (*PreciseChunkProcessor, error) {
	normalizer, err := NewPreciseLineageNormalizer(config.MaximumProcesses, config.Source)
	if err != nil {
		return nil, ErrStream
	}
	return newChunkProcessor(config, normalizer.normalizer, preciseChunkContract(normalizer))
}
