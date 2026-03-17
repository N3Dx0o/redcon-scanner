# API Keys Setup Guide

## Required Configuration

This application **requires** you to provide your own API keys via environment variables. 
Hardcoded API keys have been removed for security reasons.

## Required API Keys

### OpenAI API Key (Required)

The application needs an OpenAI API key to function.

**Get your key:**
1. Go to https://platform.openai.com/api-keys
2. Sign in or create an account
3. Click "Create new secret key"
4. Copy the key (starts with `sk-`)

**Set the environment variable:**

**Linux/Mac:**
```bash
export OPENAI_API_KEY="sk-your-key-here"
```

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-key-here"
```

**Windows (Command Prompt):**
```cmd
set OPENAI_API_KEY=sk-your-key-here
```

## Optional API Keys

### Anthropic (Claude Models)
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```
Get from: https://console.anthropic.com/

### Google Gemini
```bash
export GEMINI_API_KEY="your-key-here"
```
Get from: https://aistudio.google.com/app/apikey

### xAI (Grok)
```bash
export XAI_API_KEY="xai-your-key-here"
```

### DeepSeek
```bash
export DEEPSEEK_API_KEY="your-key-here"
```

### Ollama (Local Models)
```bash
export OLLAMA_BASE_URL="http://localhost:11434/"
```
No API key needed for local Ollama models.

## Permanent Setup

### Make Environment Variables Permanent

**Linux/Mac (bash):**
Add to `~/.bashrc` or `~/.bash_profile`:
```bash
echo 'export OPENAI_API_KEY="sk-your-key-here"' >> ~/.bashrc
source ~/.bashrc
```

**Linux/Mac (zsh):**
Add to `~/.zshrc`:
```bash
echo 'export OPENAI_API_KEY="sk-your-key-here"' >> ~/.zshrc
source ~/.zshrc
```

**Windows:**
1. Search for "Environment Variables" in Start menu
2. Click "Edit the system environment variables"
3. Click "Environment Variables" button
4. Add new variable: `OPENAI_API_KEY` with your key

## Running the Application

Once your API keys are set:

```bash
# Activate virtual environment
source venv/bin/activate

# Run the application
python run.py --port 3333
```

## Verification

To verify your API key is set:

**Linux/Mac:**
```bash
echo $OPENAI_API_KEY
```

**Windows (PowerShell):**
```powershell
echo $env:OPENAI_API_KEY
```

## Security Best Practices

✅ **DO:**
- Use environment variables for API keys
- Keep keys private and secure
- Set usage limits in your API account
- Rotate keys periodically
- Use `.gitignore` to prevent committing keys

❌ **DON'T:**
- Hardcode API keys in source code
- Commit API keys to version control
- Share API keys publicly
- Use the same key across multiple applications

## Troubleshooting

**Error: "Required API keys are not set!"**
- Make sure you've exported the OPENAI_API_KEY environment variable
- Verify the variable is set: `echo $OPENAI_API_KEY`
- Restart your terminal after setting environment variables

**API Key Not Working:**
- Check that your key is valid at https://platform.openai.com/api-keys
- Verify your OpenAI account has available credits
- Ensure there are no extra spaces or quotes in the key

## Support

For more information about the application, see `README.md`
