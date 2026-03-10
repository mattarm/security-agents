#!/bin/bash
# SecurityAgents Platform Installation Script

set -e

echo "🚀 SecurityAgents Platform Installation"
echo "======================================="

# Check Python version
python_version=$(python3 -V 2>&1 | grep -o '[0-9]\.[0-9]*')
if [[ $(echo "$python_version >= 3.8" | bc) -eq 0 ]]; then
    echo "❌ Error: Python 3.8 or higher is required (found $python_version)"
    exit 1
fi
echo "✅ Python $python_version detected"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Create symbolic links for import compatibility
echo "🔗 Creating import compatibility links..."
if [ ! -L "mcp_integration" ]; then
    ln -sf mcp-integration mcp_integration
fi

if [ ! -L "mcp_integration/slack_workflows" ]; then
    ln -sf slack-workflows mcp_integration/slack_workflows
fi

# Create directories for logs and config
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p config
mkdir -p data

# Create sample configuration files
echo "⚙️ Creating sample configuration files..."

# Create .env template if it doesn't exist
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# SecurityAgents Platform Configuration
# Copy this to .env.local and configure your credentials

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-west-2

# CrowdStrike Configuration
CROWDSTRIKE_CLIENT_ID=your_crowdstrike_client_id
CROWDSTRIKE_CLIENT_SECRET=your_crowdstrike_client_secret
CROWDSTRIKE_BASE_URL=https://api.crowdstrike.com

# GitHub Configuration
GITHUB_TOKEN=your_github_personal_access_token
GITHUB_ORG=your_github_organization

# Slack Configuration
SLACK_BOT_TOKEN=xoxb-your-slack-bot-token
SLACK_APP_TOKEN=xapp-your-slack-app-token
SLACK_SIGNING_SECRET=your_slack_signing_secret

# Atlassian Configuration
ATLASSIAN_EMAIL=your_atlassian_email
ATLASSIAN_API_TOKEN=your_atlassian_api_token
ATLASSIAN_BASE_URL=https://your-domain.atlassian.net

# Tines Configuration
TINES_BASE_URL=https://your-tenant.tines.com
TINES_API_TOKEN=your_tines_api_token

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=logs/security_agents.log
EOF
    echo "📝 Created .env template - copy to .env.local and configure"
fi

# Create basic config file
cat > config/default.yaml << 'EOF'
# SecurityAgents Platform Default Configuration
platform:
  name: "SecurityAgents Platform"
  version: "2.0.0"
  environment: "development"

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "logs/security_agents.log"

mcp_servers:
  crowdstrike:
    enabled: true
    timeout: 30
    retry_attempts: 3
  
  aws:
    enabled: true
    timeout: 30
    retry_attempts: 3
  
  github:
    enabled: true
    timeout: 30
    retry_attempts: 3
    
  slack:
    enabled: true
    timeout: 30
    retry_attempts: 3

rate_limiting:
  default_requests_per_minute: 60
  default_requests_per_hour: 1000
  burst_limit: 10

circuit_breaker:
  failure_threshold: 5
  recovery_timeout: 60
  success_threshold: 3
EOF

# Run tests to verify installation
echo "🧪 Running installation verification tests..."
PYTHONPATH=. python3 run_example.py

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "💡 Next steps:"
echo "   1. Copy .env to .env.local and configure your API credentials"
echo "   2. Update config/default.yaml with your specific settings" 
echo "   3. Run: source venv/bin/activate && PYTHONPATH=. python3 run_example.py"
echo "   4. Start using the SecurityAgents platform!"
echo ""
echo "📚 Documentation: ./README.md"
echo "🔧 Configuration: ./.env.local, ./config/default.yaml"
echo "📊 Logs: ./logs/"
echo ""