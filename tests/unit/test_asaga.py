"""Unit tests for Adaptive Simulated Annealing Genetic Algorithm (ASAGA)."""

import pytest
from adam.evolution.asaga import ASAGAOptimizer, SandboxGenome


def test_asaga_optimizer_initialization():
    optimizer = ASAGAOptimizer(population_size=8, initial_temperature=50.0, seed=42)
    assert len(optimizer.population) == 8
    assert optimizer.temperature == 50.0
    assert optimizer.generation_count == 0


def test_asaga_fitness_computation():
    optimizer = ASAGAOptimizer(population_size=5, seed=42)
    genome = optimizer.population[0]

    # Non-crashed sample
    fitness = optimizer.compute_fitness(
        genome=genome,
        novel_behaviors=3,
        iocs_extracted=2,
        overhead_ms=120.0,
        system_crashed=False,
    )
    # (15 * 3) + (25 * 2) - (0.05 * 120) = 45 + 50 - 6 = 89.0
    assert fitness == 89.0
    assert genome.fitness_score == 89.0

    # Crashed sample
    crashed_fitness = optimizer.compute_fitness(
        genome=genome,
        novel_behaviors=1,
        iocs_extracted=1,
        overhead_ms=50.0,
        system_crashed=True,
    )
    assert crashed_fitness == -100.0


def test_asaga_diversity_and_evolution_cycle():
    optimizer = ASAGAOptimizer(
        population_size=6,
        initial_temperature=100.0,
        cooling_rate=0.9,
        diversity_threshold=0.01,
        seed=100,
    )

    # Assign fitnesses
    for i, g in enumerate(optimizer.population):
        optimizer.compute_fitness(g, novel_behaviors=i, iocs_extracted=i + 1, overhead_ms=50.0)

    diversity_before = optimizer.calculate_population_diversity()
    assert diversity_before >= 0.0

    # Run evolution step
    res = optimizer.evolve_generation()
    assert res.generation == 1
    assert len(res.population) == 6
    assert res.metrics.temperature < 100.0
    assert res.best_genome is not None
