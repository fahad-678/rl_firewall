import torch
import torch.nn as nn
import torch.nn.functional as F

class FirewallDQN(nn.Module):
    def __init__(self, input_dim=10, output_dim=3):
        """
        Input: 10-dimensional state vector from FlowManager.
        Output: Q-values for 3 discrete actions (Accept, Drop, Rate Limit).
        """
        super(FirewallDQN, self).__init__()
        
        # We keep the network relatively shallow to ensure sub-millisecond 
        # inference times, avoiding the latency penalty in the reward function.
        self.fc1 = nn.Linear(input_dim, 64)
        self.fc2 = nn.Linear(64, 64)
        self.fc3 = nn.Linear(64, output_dim)

    def forward(self, x):
        # Pass state through hidden layers with ReLU activation
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        # The output layer returns the raw Q-values for each action
        return self.fc3(x)