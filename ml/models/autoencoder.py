import torch
import torch.nn as nn
import numpy as np
from pathlib import Path

class IoTAnomalyAutoencoder(nn.Module):
    """
    Deep Autoencoder for Unsupervised IoT Network Anomaly Detection.
    Trained exclusively on benign traffic to reconstruct normal flow patterns.
    High reconstruction error indicates abnormal or malicious traffic.
    """
    def __init__(self, input_dim: int = 46, latent_dim: int = 8):
        super(IoTAnomalyAutoencoder, self).__init__()
        
        # Encoder: Compresses 46 features down to latent space (46 -> 32 -> 16 -> 8)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.1),
            
            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),
            
            nn.Linear(16, latent_dim),
            nn.LeakyReLU(0.1)
        )
        
        # Decoder: Reconstructs normal profile (8 -> 16 -> 32 -> 46)
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),
            
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.1),
            
            nn.Linear(32, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def compute_reconstruction_error(self, x: torch.Tensor) -> np.ndarray:
        """
        Calculates Mean Squared Error (MSE) per flow.
        """
        self.eval()
        with torch.no_grad():
            x_recon = self.forward(x)
            mse = torch.mean((x - x_recon) ** 2, dim=1)
            return mse.cpu().numpy()

    def get_feature_deviations(self, x: torch.Tensor) -> np.ndarray:
        """
        Calculates squared error per individual feature to provide explainability.
        """
        self.eval()
        with torch.no_grad():
            x_recon = self.forward(x)
            dev = ((x - x_recon) ** 2).cpu().numpy()
            return dev
