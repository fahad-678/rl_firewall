import math
import random
import torch
import torch.nn as nn
import torch.optim as optim
from .model import FirewallDQN
from .replay_buffer import ExperienceReplay

class DQNAgent:
    def __init__(self, input_dim=10, action_dim=3, lr=1e-3, gamma=0.99, batch_size=64):
        self.action_dim = action_dim
        self.gamma = gamma       # Discount factor for future rewards
        self.batch_size = batch_size
        
        # Exploration parameters (epsilon-greedy)
        self.epsilon_start = 0.9
        self.epsilon_end = 0.05
        self.epsilon_decay = 1000
        self.steps_done = 0

        # Primary Policy Network and Frozen Target Network
        self.policy_net = FirewallDQN(input_dim, action_dim)
        self.target_net = FirewallDQN(input_dim, action_dim)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval() # Target network does not track gradients

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.memory = ExperienceReplay(capacity=50000)

    def select_action(self, state_vector):
        """Epsilon-greedy action selection."""
        sample = random.random()
        # Calculate decaying epsilon
        eps_threshold = self.epsilon_end + (self.epsilon_start - self.epsilon_end) * \
            math.exp(-1. * self.steps_done / self.epsilon_decay)
        self.steps_done += 1

        if sample > eps_threshold:
            # Exploit: Choose action with maximum computed Q-value
            with torch.no_grad():
                state_tensor = torch.tensor([state_vector], dtype=torch.float32)
                q_values = self.policy_net(state_tensor)
                return q_values.max(1)[1].item()
        else:
            # Explore: Select a completely random action
            return random.randrange(self.action_dim)

    def optimize_model(self):
        """Performs a single step of optimization using the Bellman equation."""
        if len(self.memory) < self.batch_size:
            return # Wait until we have enough memory
            
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)

        # Compute current Q values from the policy network
        current_q_values = self.policy_net(states).gather(1, actions)

        # Compute next Q values from the frozen target network
        with torch.no_grad():
            max_next_q_values = self.target_net(next_states).max(1)[0].unsqueeze(1)
            
        # Compute the expected Q values (Bellman target)
        # If the state is terminal (done=1), future reward is 0
        expected_q_values = rewards + (self.gamma * max_next_q_values * (1 - dones))

        # Compute Huber loss (Smooth L1 Loss) for stability
        criterion = nn.SmoothL1Loss()
        loss = criterion(current_q_values, expected_q_values)

        # Backpropagation
        self.optimizer.zero_grad()
        loss.backward()
        # Gradient clipping to prevent exploding gradients
        for param in self.policy_net.parameters():
            param.grad.data.clamp_(-1, 1)
        self.optimizer.step()

    def update_target_network(self):
        """Synchronizes the frozen target network with the primary network."""
        self.target_net.load_state_dict(self.policy_net.state_dict())