"""Adaptive Simulated Annealing Genetic Algorithm (ASAGA).

Optimizes Automated Moving Target Defense (AMTD) parameters across malware interaction
episodes to discover sandbox configurations that maximize intelligence gain and behavioral
novelty while preserving guest OS stability and execution speed.
Includes population diversity threshold checks to prevent premature convergence.
"""

from __future__ import annotations
import dataclasses
import math
import random
from typing import Dict, List, Optional, Tuple


@dataclasses.dataclass
class SandboxGenome:
    genome_id: str
    syscall_randomize_rate: float  # 0.0 to 1.0
    memory_shuffle_interval_s: float  # 1.0 to 60.0
    decoy_density: int  # 1 to 20 lures
    mitigation_spectre: bool
    mitigation_meltdown: bool
    c2_sinkhole_mode: str  # PASSIVE, ACTIVE_SPOOF, INTERACTIVE_EMULATOR
    tsc_compensation_enabled: bool
    user_simulation_intensity: float  # 0.0 to 1.0
    fitness_score: float = 0.0
    novelty_score: float = 0.0
    intelligence_gain: int = 0
    overhead_ms: float = 0.0


@dataclasses.dataclass
class EvolutionMetrics:
    generation: int
    best_fitness: float
    average_fitness: float
    population_diversity: float
    temperature: float
    novel_behaviors_discovered: int


@dataclasses.dataclass
class GenerationResult:
    generation: int
    best_genome: SandboxGenome
    metrics: EvolutionMetrics
    population: List[SandboxGenome]


class ASAGAOptimizer:
    """Manages the evolutionary optimization of the sandbox configuration population."""

    def __init__(
        self,
        population_size: int = 10,
        initial_temperature: float = 100.0,
        cooling_rate: float = 0.92,
        min_temperature: float = 0.01,
        diversity_threshold: float = 0.15,
        seed: Optional[int] = None,
    ) -> None:
        self.population_size = population_size
        self.temperature = initial_temperature
        self.cooling_rate = cooling_rate
        self.min_temperature = min_temperature
        self.diversity_threshold = diversity_threshold
        self.rng = random.Random(seed)
        self.generation_count = 0
        self.population: List[SandboxGenome] = self._initialize_population()

    def _initialize_population(self) -> List[SandboxGenome]:
        pop = []
        sinkhole_modes = ["PASSIVE", "ACTIVE_SPOOF", "INTERACTIVE_EMULATOR"]
        for i in range(self.population_size):
            genome = SandboxGenome(
                genome_id=f"g0_{i}",
                syscall_randomize_rate=round(self.rng.uniform(0.1, 0.9), 3),
                memory_shuffle_interval_s=round(self.rng.uniform(5.0, 45.0), 1),
                decoy_density=self.rng.randint(2, 15),
                mitigation_spectre=self.rng.choice([True, False]),
                mitigation_meltdown=self.rng.choice([True, False]),
                c2_sinkhole_mode=self.rng.choice(sinkhole_modes),
                tsc_compensation_enabled=True,
                user_simulation_intensity=round(self.rng.uniform(0.2, 0.8), 2),
            )
            pop.append(genome)
        return pop

    def compute_fitness(
        self,
        genome: SandboxGenome,
        novel_behaviors: int,
        iocs_extracted: int,
        overhead_ms: float,
        system_crashed: bool = False,
    ) -> float:
        """Calculates multi-objective fitness score:

        Fitness = (w1 * Novelty) + (w2 * IOC_Gain) - (w3 * Latency_Overhead) - (Penalty * Crashed)
        """
        if system_crashed:
            genome.fitness_score = -100.0
            return genome.fitness_score

        w_novelty = 15.0
        w_iocs = 25.0
        w_overhead = 0.05

        score = (w_novelty * novel_behaviors) + (w_iocs * iocs_extracted) - (w_overhead * overhead_ms)
        genome.novelty_score = float(novel_behaviors)
        genome.intelligence_gain = iocs_extracted
        genome.overhead_ms = overhead_ms
        genome.fitness_score = round(score, 3)
        return genome.fitness_score

    def calculate_population_diversity(self) -> float:
        """Calculates pairwise normalized gene variance across the current population."""
        if len(self.population) < 2:
            return 1.0

        n = len(self.population)
        syscall_rates = [g.syscall_randomize_rate for g in self.population]
        mem_intervals = [g.memory_shuffle_interval_s / 60.0 for g in self.population]
        decoy_ratios = [g.decoy_density / 20.0 for g in self.population]

        var_syscall = sum((x - sum(syscall_rates) / n) ** 2 for x in syscall_rates) / n
        var_mem = sum((x - sum(mem_intervals) / n) ** 2 for x in mem_intervals) / n
        var_decoy = sum((x - sum(decoy_ratios) / n) ** 2 for x in decoy_ratios) / n

        avg_var = (var_syscall + var_mem + var_decoy) / 3.0
        return round(math.sqrt(avg_var), 4)

    def inject_diversity_boost(self) -> None:
        """Prevents premature convergence by mutating low-fitness genomes when diversity drops below threshold."""
        sinkhole_modes = ["PASSIVE", "ACTIVE_SPOOF", "INTERACTIVE_EMULATOR"]
        self.population.sort(key=lambda g: g.fitness_score, reverse=True)
        # Mutate bottom 40% of population
        start_idx = int(self.population_size * 0.6)
        for i in range(start_idx, self.population_size):
            old = self.population[i]
            self.population[i] = SandboxGenome(
                genome_id=f"g{self.generation_count}_boost_{i}",
                syscall_randomize_rate=round(self.rng.uniform(0.1, 0.95), 3),
                memory_shuffle_interval_s=round(self.rng.uniform(2.0, 50.0), 1),
                decoy_density=self.rng.randint(3, 18),
                mitigation_spectre=self.rng.choice([True, False]),
                mitigation_meltdown=self.rng.choice([True, False]),
                c2_sinkhole_mode=self.rng.choice(sinkhole_modes),
                tsc_compensation_enabled=True,
                user_simulation_intensity=round(self.rng.uniform(0.1, 0.9), 2),
            )

    def crossover(self, parent_a: SandboxGenome, parent_b: SandboxGenome, child_id: str) -> SandboxGenome:
        """Performs uniform genetic crossover between two sandbox configurations."""
        return SandboxGenome(
            genome_id=child_id,
            syscall_randomize_rate=self.rng.choice([parent_a.syscall_randomize_rate, parent_b.syscall_randomize_rate]),
            memory_shuffle_interval_s=round((parent_a.memory_shuffle_interval_s + parent_b.memory_shuffle_interval_s) / 2.0, 1),
            decoy_density=self.rng.choice([parent_a.decoy_density, parent_b.decoy_density]),
            mitigation_spectre=parent_a.mitigation_spectre if self.rng.random() > 0.5 else parent_b.mitigation_spectre,
            mitigation_meltdown=parent_a.mitigation_meltdown if self.rng.random() > 0.5 else parent_b.mitigation_meltdown,
            c2_sinkhole_mode=self.rng.choice([parent_a.c2_sinkhole_mode, parent_b.c2_sinkhole_mode]),
            tsc_compensation_enabled=True,
            user_simulation_intensity=round((parent_a.user_simulation_intensity + parent_b.user_simulation_intensity) / 2.0, 2),
        )

    def mutate(self, genome: SandboxGenome) -> SandboxGenome:
        """Applies adaptive mutation to a genome."""
        mutation_rate = 0.25
        if self.rng.random() < mutation_rate:
            genome.syscall_randomize_rate = min(1.0, max(0.05, genome.syscall_randomize_rate + self.rng.uniform(-0.15, 0.15)))
        if self.rng.random() < mutation_rate:
            genome.memory_shuffle_interval_s = min(60.0, max(2.0, genome.memory_shuffle_interval_s + self.rng.uniform(-5.0, 5.0)))
        if self.rng.random() < mutation_rate:
            genome.decoy_density = max(1, min(20, genome.decoy_density + self.rng.randint(-2, 2)))
        return genome

    def evolve_generation(self) -> GenerationResult:
        """Executes one complete ASAGA generation cycle: selection, annealing, crossover, mutation."""
        self.generation_count += 1
        self.population.sort(key=lambda g: g.fitness_score, reverse=True)

        best_genome = self.population[0]
        avg_fitness = sum(g.fitness_score for g in self.population) / len(self.population)
        diversity = self.calculate_population_diversity()

        # Simulated Annealing: Check if lower-fitness solutions should be explored
        new_population: List[SandboxGenome] = [best_genome]  # Elitism

        while len(new_population) < self.population_size:
            # Tournament selection
            candidates = self.rng.sample(self.population, min(3, len(self.population)))
            candidates.sort(key=lambda g: g.fitness_score, reverse=True)
            p1 = candidates[0]
            p2 = candidates[1] if len(candidates) > 1 else candidates[0]

            # Annealing acceptance criterion
            delta = p2.fitness_score - p1.fitness_score
            if delta < 0 and self.temperature > self.min_temperature:
                acceptance_prob = math.exp(delta / self.temperature)
                if self.rng.random() < acceptance_prob:
                    p1 = p2  # Accept inferior parent to escape local optima

            child = self.crossover(p1, p2, f"g{self.generation_count}_{len(new_population)}")
            child = self.mutate(child)
            new_population.append(child)

        self.population = new_population

        # Check diversity threshold
        if diversity < self.diversity_threshold:
            self.inject_diversity_boost()

        # Cool temperature
        self.temperature = max(self.min_temperature, self.temperature * self.cooling_rate)

        metrics = EvolutionMetrics(
            generation=self.generation_count,
            best_fitness=best_genome.fitness_score,
            average_fitness=round(avg_fitness, 3),
            population_diversity=diversity,
            temperature=round(self.temperature, 4),
            novel_behaviors_discovered=int(best_genome.novelty_score),
        )

        return GenerationResult(
            generation=self.generation_count,
            best_genome=best_genome,
            metrics=metrics,
            population=self.population,
        )
