import math
import random
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
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

        self.state_cache = {}
        
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
    
    def get_confidence(self, state_vector):
        """
        Converts the raw Q-values of the current state into a confidence percentage.
        """
        with torch.no_grad(): # No need to track gradients for inference
            state_tensor = torch.tensor([state_vector], dtype=torch.float32)
            
            # 1. Get the raw Q-values from the neural network
            q_values = self.policy_net(state_tensor)
            
            # 2. Apply Softmax to squish Q-values into probabilities (0.0 to 1.0)
            probabilities = F.softmax(q_values, dim=1)
            
            # 3. Extract the probability of the *chosen* action (the highest value)
            confidence_score = probabilities.max().item()
            
            return confidence_score
    def apply_human_feedback(self, src_ip, correct_action_label, original_action_label=None):
        """
        Forces the DQN to update its weights based on human analyst intervention.
        """
        # 1. Map the string labels from Vue/Laravel to your AI's integer action space
        action_map = {'ALLOW': 0, 'BLOCK': 1, 'RATE_LIMIT': 2, 'NEEDS_REVIEW': 3}
        correct_action = action_map.get(correct_action_label.upper())
        original_action = action_map.get(original_action_label.upper()) if original_action_label else None

        # 2. Retrieve the state vector (the packet features) that caused the incident
        # Note: You must ensure flow_manager.py or your agent caches the last known state per IP
        state = self.state_cache.get(src_ip)
        
        if state is None:
            print(f"[!] Warning: State for {src_ip} dropped from memory cache. Cannot retrain.")
            return

        # 3. Memory Injection (The actual Reinforcement)
        # We forcefully inject extreme rewards into the replay buffer to override the AI's bias
        
        # Reward the human's correct choice heavily
        self.memory.add(state, correct_action, reward=100.0, next_state=state, done=True)
        
        # Penalize the AI's original mistake severely (if we know it)
        if original_action is not None and original_action != correct_action:
            self.memory.add(state, original_action, reward=-100.0, next_state=state, done=True)

        # 4. Immediate Retraining (Online Learning Spike)
        # Instead of waiting for the next random batch, we force the network to train
        # several times right now so the weights adjust before the next packet arrives.
        print(f"[*] Human Override: Adjusting neural weights for {src_ip} pattern -> {correct_action_label}")
        
        for _ in range(5): # Mini-epoch spike
            self.replay(batch_size=32)
            
        # Optional: Save the new weights to disk so it doesn't forget on reboot
        self.save("firewall_dqn_weights.h5")