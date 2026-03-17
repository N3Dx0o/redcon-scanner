from typing import Annotated


async def adversarial_attack_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the ML function does, its purpose in machine learning, and its role in the ML pipeline. Should include ML operations, model training/inference, and any ML-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the ML function including all statements, variable assignments, control flow, function calls, ML operations, and any nested logic. This is the actual ML code that will be analyzed for adversarial vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'ml/models/classifier.py', 'ai/inference/predictor.py', 'models/neural_network.py'). Used for context and reporting."], 
    ml_context: Annotated[str, "Additional ML context including the ML framework (e.g., TensorFlow, PyTorch, Scikit-learn), model type (e.g., neural network, decision tree, SVM), and critical ML operations this function handles."],
    list_of_adversarial_threats: Annotated[list[str], "A comprehensive list of adversarial attack threats and vulnerabilities to check for during analysis. Each item should be a specific adversarial threat type (e.g., 'Adversarial Examples', 'Model Evasion Attacks', 'Model Poisoning Attacks', 'Backdoor Attacks', 'Data Poisoning', 'Model Extraction Attacks', 'Membership Inference Attacks', 'Model Inversion Attacks', 'Property Inference Attacks', 'Model Stealing Attacks', 'Model Watermarking Attacks', 'Model Robustness Issues', 'Adversarial Training Vulnerabilities', 'Defense Evasion', 'Transferability Attacks', 'Black Box Attacks', 'White Box Attacks', 'Gray Box Attacks', 'Query-Based Attacks', 'Gradient-Based Attacks', 'Optimization-Based Attacks', 'Decision-Based Attacks', 'Score-Based Attacks', 'Boundary-Based Attacks', 'Surrogate Model Attacks', 'Ensemble Attacks', 'Adaptive Attacks', 'Universal Adversarial Perturbations', 'Adversarial Patches', 'Physical Adversarial Examples', 'Adversarial Text', 'Adversarial Images', 'Adversarial Audio', 'Adversarial Video', 'Adversarial Tabular Data', 'Adversarial Time Series', 'Adversarial Graph Data', 'Adversarial Reinforcement Learning', 'Adversarial Generative Models', 'Adversarial Autoencoders', 'Adversarial GANs', 'Adversarial VAEs', 'Adversarial Transformers', 'Adversarial CNNs', 'Adversarial RNNs', 'Adversarial LSTMs', 'Adversarial GRUs', 'Adversarial Attention Mechanisms', 'Adversarial Self-Attention', 'Adversarial Multi-Head Attention', 'Adversarial Positional Encoding', 'Adversarial Layer Normalization', 'Adversarial Dropout', 'Adversarial Batch Normalization', 'Adversarial Activation Functions', 'Adversarial Loss Functions', 'Adversarial Optimizers', 'Adversarial Learning Rates', 'Adversarial Regularization', 'Adversarial Data Augmentation', 'Adversarial Feature Engineering', 'Adversarial Feature Selection', 'Adversarial Dimensionality Reduction', 'Adversarial Clustering', 'Adversarial Classification', 'Adversarial Regression', 'Adversarial Anomaly Detection', 'Adversarial Recommendation Systems', 'Adversarial Natural Language Processing', 'Adversarial Computer Vision', 'Adversarial Speech Processing', 'Adversarial Time Series Analysis', 'Adversarial Graph Analysis', 'Adversarial Reinforcement Learning', 'Adversarial Multi-Agent Systems', 'Adversarial Federated Learning', 'Adversarial Distributed Learning', 'Adversarial Edge Computing', 'Adversarial IoT', 'Adversarial Mobile Computing', 'Adversarial Cloud Computing', 'Adversarial Edge AI', 'Adversarial TinyML', 'Adversarial On-Device Learning', 'Adversarial Federated Learning', 'Adversarial Differential Privacy', 'Adversarial Homomorphic Encryption', 'Adversarial Secure Multi-Party Computation', 'Adversarial Zero-Knowledge Proofs', 'Adversarial Blockchain', 'Adversarial Smart Contracts', 'Adversarial DeFi', 'Adversarial NFTs', 'Adversarial DAOs', 'Adversarial Web3', 'Adversarial Metaverse', 'Adversarial AR/VR', 'Adversarial Robotics', 'Adversarial Autonomous Systems', 'Adversarial Self-Driving Cars', 'Adversarial Drones', 'Adversarial IoT Devices', 'Adversarial Smart Cities', 'Adversarial Healthcare AI', 'Adversarial Financial AI', 'Adversarial Legal AI', 'Adversarial Educational AI', 'Adversarial Entertainment AI', 'Adversarial Gaming AI', 'Adversarial Social Media AI', 'Adversarial Search AI', 'Adversarial Recommendation AI', 'Adversarial Content AI', 'Adversarial Creative AI', 'Adversarial Generative AI', 'Adversarial Conversational AI', 'Adversarial Multimodal AI', 'Adversarial Cross-Modal AI', 'Adversarial Transfer Learning', 'Adversarial Meta-Learning', 'Adversarial Few-Shot Learning', 'Adversarial Zero-Shot Learning', 'Adversarial One-Shot Learning', 'Adversarial Multi-Task Learning', 'Adversarial Multi-Domain Learning', 'Adversarial Multi-Lingual Learning', 'Adversarial Cross-Lingual Learning', 'Adversarial Cross-Cultural Learning', 'Adversarial Cross-Domain Learning', 'Adversarial Cross-Modal Learning', 'Adversarial Cross-Task Learning', 'Adversarial Cross-Lingual Learning', 'Adversarial Cross-Cultural Learning', 'Adversarial Cross-Domain Learning', 'Adversarial Cross-Modal Learning', 'Adversarial Cross-Task Learning', etc.)."]
) -> str:
    """
    Analyze an ML function for adversarial attack vulnerabilities and threats.
    
    This function focuses specifically on adversarial attacks, ML security issues,
    and ML-specific attack vectors that could lead to model compromise,
    data poisoning, or exploitation of ML functionality.
    
    Args:
        function_explanation: Human-readable description of the ML function's purpose and behavior
        function_body: Complete source code of the ML function to be analyzed
        file_path: Full path to the file containing the ML function for context
        ml_context: Additional ML context and ML implementation information
        list_of_adversarial_threats: List of specific adversarial threats to evaluate
        
    Returns:
        str: Detailed adversarial analysis report including identified vulnerabilities,
             adversarial-specific attack vector analysis, potential ML impact, and remediation
             recommendations specific to ML security.
             
    Example:
        result = await adversarial_attack_threats(
            function_explanation="Image classification model with CNN architecture for object detection",
            function_body="def predict(image): return model.predict(preprocess(image))",
            file_path="ml/models/classifier.py",
            ml_context="TensorFlow CNN model for image classification with adversarial training",
            list_of_adversarial_threats=["Adversarial Examples", "Model Evasion Attacks", "Model Poisoning Attacks", "Backdoor Attacks"]
        )
        
    Note:
        This function should be used for analyzing ML functions, ML models,
        and ML-specific code where vulnerabilities could lead to ML compromise
        or ML functionality exploitation. Focus on ML security best practices.
    """
    msg = f"""
ADVERSARIAL ATTACK THREAT ANALYSIS REQUEST

Function Context:
- ML Purpose: {function_explanation}
- File Location: {file_path}
- ML Context: {ml_context}
- Adversarial Threats to Evaluate: {', '.join(list_of_adversarial_threats)}

ML Source Code to Analyze:
{function_body}

Please perform a comprehensive adversarial attack analysis focusing on the specified threats and provide detailed findings with adversarial-specific attack vector analysis, potential ML impact, and remediation guidance specific to ML security vulnerabilities and secure ML development practices.
"""

    return msg


async def model_poisoning_threats(
    function_explanation: Annotated[str, "A clear, human-readable explanation of what the ML training function does, its purpose in model training, and its role in the ML pipeline. Should include training operations, data processing, and any training-specific security behaviors."],
    function_body: Annotated[str, "The complete source code of the ML training function including all statements, variable assignments, control flow, function calls, training operations, and any nested logic. This is the actual training code that will be analyzed for poisoning vulnerabilities."], 
    file_path: Annotated[str, "The full relative path from the project root to the file containing this function (e.g., 'ml/training/trainer.py', 'ai/models/train.py', 'training/neural_network.py'). Used for context and reporting."], 
    training_context: Annotated[str, "Additional training context including the training approach (e.g., supervised, unsupervised, reinforcement), data sources, and critical training operations this function handles."],
    list_of_poisoning_threats: Annotated[list[str], "A comprehensive list of model poisoning threats and vulnerabilities to check for during analysis. Each item should be a specific poisoning threat type (e.g., 'Data Poisoning', 'Label Poisoning', 'Feature Poisoning', 'Model Poisoning', 'Backdoor Attacks', 'Trojan Attacks', 'Steganography Attacks', 'Watermarking Attacks', 'Fingerprinting Attacks', 'Model Extraction Attacks', 'Model Inversion Attacks', 'Membership Inference Attacks', 'Property Inference Attacks', 'Model Stealing Attacks', 'Model Watermarking Attacks', 'Model Robustness Issues', 'Adversarial Training Vulnerabilities', 'Defense Evasion', 'Transferability Attacks', 'Black Box Attacks', 'White Box Attacks', 'Gray Box Attacks', 'Query-Based Attacks', 'Gradient-Based Attacks', 'Optimization-Based Attacks', 'Decision-Based Attacks', 'Score-Based Attacks', 'Boundary-Based Attacks', 'Surrogate Model Attacks', 'Ensemble Attacks', 'Adaptive Attacks', 'Universal Adversarial Perturbations', 'Adversarial Patches', 'Physical Adversarial Examples', 'Adversarial Text', 'Adversarial Images', 'Adversarial Audio', 'Adversarial Video', 'Adversarial Tabular Data', 'Adversarial Time Series', 'Adversarial Graph Data', 'Adversarial Reinforcement Learning', 'Adversarial Generative Models', 'Adversarial Autoencoders', 'Adversarial GANs', 'Adversarial VAEs', 'Adversarial Transformers', 'Adversarial CNNs', 'Adversarial RNNs', 'Adversarial LSTMs', 'Adversarial GRUs', 'Adversarial Attention Mechanisms', 'Adversarial Self-Attention', 'Adversarial Multi-Head Attention', 'Adversarial Positional Encoding', 'Adversarial Layer Normalization', 'Adversarial Dropout', 'Adversarial Batch Normalization', 'Adversarial Activation Functions', 'Adversarial Loss Functions', 'Adversarial Optimizers', 'Adversarial Learning Rates', 'Adversarial Regularization', 'Adversarial Data Augmentation', 'Adversarial Feature Engineering', 'Adversarial Feature Selection', 'Adversarial Dimensionality Reduction', 'Adversarial Clustering', 'Adversarial Classification', 'Adversarial Regression', 'Adversarial Anomaly Detection', 'Adversarial Recommendation Systems', 'Adversarial Natural Language Processing', 'Adversarial Computer Vision', 'Adversarial Speech Processing', 'Adversarial Time Series Analysis', 'Adversarial Graph Analysis', 'Adversarial Reinforcement Learning', 'Adversarial Multi-Agent Systems', 'Adversarial Federated Learning', 'Adversarial Distributed Learning', 'Adversarial Edge Computing', 'Adversarial IoT', 'Adversarial Mobile Computing', 'Adversarial Cloud Computing', 'Adversarial Edge AI', 'Adversarial TinyML', 'Adversarial On-Device Learning', 'Adversarial Federated Learning', 'Adversarial Differential Privacy', 'Adversarial Homomorphic Encryption', 'Adversarial Secure Multi-Party Computation', 'Adversarial Zero-Knowledge Proofs', 'Adversarial Blockchain', 'Adversarial Smart Contracts', 'Adversarial DeFi', 'Adversarial NFTs', 'Adversarial DAOs', 'Adversarial Web3', 'Adversarial Metaverse', 'Adversarial AR/VR', 'Adversarial Robotics', 'Adversarial Autonomous Systems', 'Adversarial Self-Driving Cars', 'Adversarial Drones', 'Adversarial IoT Devices', 'Adversarial Smart Cities', 'Adversarial Healthcare AI', 'Adversarial Financial AI', 'Adversarial Legal AI', 'Adversarial Educational AI', 'Adversarial Entertainment AI', 'Adversarial Gaming AI', 'Adversarial Social Media AI', 'Adversarial Search AI', 'Adversarial Recommendation AI', 'Adversarial Content AI', 'Adversarial Creative AI', 'Adversarial Generative AI', 'Adversarial Conversational AI', 'Adversarial Multimodal AI', 'Adversarial Cross-Modal AI', 'Adversarial Transfer Learning', 'Adversarial Meta-Learning', 'Adversarial Few-Shot Learning', 'Adversarial Zero-Shot Learning', 'Adversarial One-Shot Learning', 'Adversarial Multi-Task Learning', 'Adversarial Multi-Domain Learning', 'Adversarial Multi-Lingual Learning', 'Adversarial Cross-Lingual Learning', 'Adversarial Cross-Cultural Learning', 'Adversarial Cross-Domain Learning', 'Adversarial Cross-Modal Learning', 'Adversarial Cross-Task Learning', 'Adversarial Cross-Lingual Learning', 'Adversarial Cross-Cultural Learning', 'Adversarial Cross-Domain Learning', 'Adversarial Cross-Modal Learning', 'Adversarial Cross-Task Learning', etc.)."]
) -> str:
    """
    Analyze an ML training function for model poisoning vulnerabilities and threats.
    
    This function focuses specifically on model poisoning attacks, training security issues,
    and training-specific attack vectors that could lead to model compromise,
    data corruption, or exploitation of training functionality.
    
    Args:
        function_explanation: Human-readable description of the ML training function's purpose and behavior
        function_body: Complete source code of the ML training function to be analyzed
        file_path: Full path to the file containing the ML training function for context
        training_context: Additional training context and training implementation information
        list_of_poisoning_threats: List of specific poisoning threats to evaluate
        
    Returns:
        str: Detailed poisoning analysis report including identified vulnerabilities,
             poisoning-specific attack vector analysis, potential training impact, and remediation
             recommendations specific to ML training security.
             
    Example:
        result = await model_poisoning_threats(
            function_explanation="Neural network training with backpropagation and gradient descent",
            function_body="def train_model(X, y): return model.fit(X, y, epochs=100, validation_split=0.2)",
            file_path="ml/training/trainer.py",
            training_context="TensorFlow neural network training with supervised learning",
            list_of_poisoning_threats=["Data Poisoning", "Label Poisoning", "Model Poisoning", "Backdoor Attacks"]
        )
        
    Note:
        This function should be used for analyzing ML training functions, ML training processes,
        and ML training-specific code where vulnerabilities could lead to training compromise
        or training functionality exploitation. Focus on ML training security best practices.
    """
    msg = f"""
MODEL POISONING THREAT ANALYSIS REQUEST

Function Context:
- Training Purpose: {function_explanation}
- File Location: {file_path}
- Training Context: {training_context}
- Poisoning Threats to Evaluate: {', '.join(list_of_poisoning_threats)}

ML Training Source Code to Analyze:
{function_body}

Please perform a comprehensive model poisoning analysis focusing on the specified threats and provide detailed findings with poisoning-specific attack vector analysis, potential training impact, and remediation guidance specific to ML training security vulnerabilities and secure ML training practices.
"""

    return msg
