from __future__ import annotations

import torch
import torch.nn as nn


class AnomalyCNN(nn.Module):
    """Small spectrogram CNN for host windows (T×F as 1×H×W).

    v1.1.x+: slightly deeper than the original 2-block net, with BatchNorm +
    Dropout2d. Checkpoint loaders still only need ``state_dict`` + height/width
    in ``cnn.pt`` — retrain required after this architecture change.
    """

    def __init__(
        self,
        height: int = 60,
        width: int = 30,
        n_classes: int = 2,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(1, 32, kernel_size=3, padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),
            nn.MaxPool2d(2),
            nn.Conv2d(64, 96, kernel_size=3, padding=1),
            nn.BatchNorm2d(96),
            nn.ReLU(inplace=True),
            nn.AdaptiveAvgPool2d((4, 4)),
            nn.Dropout2d(dropout),
        )
        with torch.no_grad():
            dummy = torch.zeros(1, 1, height, width)
            flat = self.features(dummy).view(1, -1).shape[1]
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(flat, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(dropout),
            nn.Linear(128, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.classifier(self.features(x))
