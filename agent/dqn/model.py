import torch
import torch.nn as nn
import torch.nn.functional as F

class FirewallDQN(nn.Module):
    def __init__(self, input_dim=16, output_dim=4):
        """
        Input: 16-dimensional state vector from FlowManager (12 original + 4 DOS indicators).
        Output: Q-values for 4 discrete actions (Allow, Block, Rate Limit, DOS Mitigate).
        """
        super(FirewallDQN, self).__init__()
        
        # Keep the model compact to minimize inference latency.
        self.fc1 = nn.Linear(input_dim, 64)
        self.fc2 = nn.Linear(64, 64)
        self.fc3 = nn.Linear(64, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.fc3(x)