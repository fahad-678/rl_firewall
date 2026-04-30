import math
import random
import torch
import os
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from .model import FirewallDQN
from .replay_buffer import ExperienceReplay
class DQNAgent:
    def __init__(self, input_dim=10, action_dim=3, lr=1e-3, gamma=0.99, batch_size=64):
        self.action_dim = action_dim
        self.gamma = gamma
        self.batch_size = batch_size
        
        # Epsilon-greedy exploration parameters.
        self.epsilon_start = 0.9
        self.epsilon_end = 0.05
        self.epsilon_decay = 1000
        self.steps_done = 0

        # Online network and frozen target network.
        self.policy_net = FirewallDQN(input_dim, action_dim)

        weight_path = "firewall_weights.pth"
        if os.path.exists(weight_path):
            print(f"[*] Loading pre-trained weights from {weight_path}")
            # Assuming you are saving state_dicts, adjust if you save the whole model
            self.policy_net.load_state_dict(torch.load(weight_path))
        else:
            print("[*] No existing weights found. Initializing fresh network.")

        self.target_net = FirewallDQN(input_dim, action_dim)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()

        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=lr)
        self.memory = ExperienceReplay(capacity=50000)

        self.state_cache = {}
        
    def select_action(self, state_vector):
        """Epsilon-greedy action selection."""
        sample = random.random()
        eps_threshold = self.epsilon_end + (self.epsilon_start - self.epsilon_end) * \
            math.exp(-1. * self.steps_done / self.epsilon_decay)
        self.steps_done += 1

        if sample > eps_threshold:
            with torch.no_grad():
                state_tensor = torch.tensor([state_vector], dtype=torch.float32)
                q_values = self.policy_net(state_tensor)
                return q_values.max(1)[1].item()
        else:
            return random.randrange(self.action_dim)

    def optimize_model(self):
        """Performs a single step of optimization using the Bellman equation."""
        if len(self.memory) < self.batch_size:
            return
            
        states, actions, rewards, next_states, dones = self.memory.sample(self.batch_size)

        current_q_values = self.policy_net(states).gather(1, actions)

        with torch.no_grad():
            max_next_q_values = self.target_net(next_states).max(1)[0].unsqueeze(1)
            
        # Bellman target.
        expected_q_values = rewards + (self.gamma * max_next_q_values * (1 - dones))

        criterion = nn.SmoothL1Loss()
        loss = criterion(current_q_values, expected_q_values)

        self.optimizer.zero_grad()
        loss.backward()
        for param in self.policy_net.parameters():
            param.grad.data.clamp_(-1, 1)
        self.optimizer.step()

    def update_target_network(self):
        """Synchronizes the frozen target network with the primary network."""
        self.target_net.load_state_dict(self.policy_net.state_dict())
    
    def get_confidence(self, state_vector, temperature=2.0):
        """
        Converts Q-values into a confidence score via temperature-scaled softmax.
        """
        with torch.no_grad():
            state_tensor = torch.tensor([state_vector], dtype=torch.float32)
            
            q_values = self.policy_net(state_tensor)
            
            probabilities = F.softmax(q_values / temperature, dim=1)
            
            confidence_score = probabilities.max().item()
            
            return confidence_score
    def apply_human_feedback(self, src_ip, correct_action_label, original_action_label=None):
        """
        Applies analyst feedback as high-priority replay samples.
        """
        action_map = {'ALLOW': 0, 'BLOCK': 1, 'RATE_LIMIT': 2, 'NEEDS_REVIEW': 3}
        correct_action = action_map.get(correct_action_label.upper())
        original_action = action_map.get(original_action_label.upper()) if original_action_label else None

        state = self.state_cache.get(src_ip)
        
        if state is None:
            print(f"[!] Warning: State for {src_ip} dropped from memory cache. Cannot retrain.")
            return

        # Bias replay toward analyst-confirmed corrections.
        self.memory.add(state, correct_action, reward=100.0, next_state=state, done=True)
        
        if original_action is not None and original_action != correct_action:
            self.memory.add(state, original_action, reward=-100.0, next_state=state, done=True)

        print(f"[*] Human Override: Adjusting neural weights for {src_ip} pattern -> {correct_action_label}")
        
        for _ in range(5):
            self.replay(batch_size=32)
            
        self.save("firewall_weights.pth")