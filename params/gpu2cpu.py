import torch
model = torch.load('model.params', map_location=lambda storage, loc: storage)
torch.save(model, './model_cpu.params')

