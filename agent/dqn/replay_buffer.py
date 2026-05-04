import random
from collections import deque
import torch

class ExperienceReplay:
    def __init__(self, capacity=10000):
        # Fixed-size buffer of recent transitions.
        self.memory = deque(maxlen=capacity)

    def push(self, state, action, reward, next_state, done):
        """Saves a transition."""
        self.memory.append((state, action, reward, next_state, done))

    def sample(self, batch_size):
        """Returns a randomized mini-batch of transitions."""
        transitions = random.sample(self.memory, batch_size)
        states, actions, rewards, next_states, dones = zip(*transitions)
        
        return (
            torch.tensor(states, dtype=torch.float32),
            torch.tensor(actions, dtype=torch.int64).unsqueeze(1),
            torch.tensor(rewards, dtype=torch.float32).unsqueeze(1),
            torch.tensor(next_states, dtype=torch.float32),
            torch.tensor(dones, dtype=torch.float32).unsqueeze(1)
        )

    def __len__(self):
        return len(self.memory)