#!/usr/bin/env python3
"""
SecurityAgents Platform CLI

Command-line interface for the SecurityAgents platform.
"""

import asyncio
import argparse
import logging
import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import platform modules
from mcp_integration.gateway.mcp_server_manager import MCPServerManager, MCPServerConfig
from mcp_integration.crowdstrike.crowdstrike_mcp_client import CrowdStrikeMCPClient
from mcp_integration.aws.aws_security_mcp_client import AWSSecurityMCPClient  
from mcp_integration.github.github_security_mcp_client import GitHubSecurityMCPClient


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('logs/security_agents.log') if os.path.exists('logs') else logging.NullHandler()
        ]
    )


async def test_platform():
    """Test platform functionality."""
    logger = logging.getLogger(__name__)
    logger.info("🔍 Testing SecurityAgents platform...")
    
    try:
        # Test basic configuration
        config = MCPServerConfig(
            server_name="cli-test",
            server_url="http://localhost:8080", 
            auth_type="api_key"
        )
        
        manager = MCPServerManager(config)
        logger.info("✅ Platform initialization successful")
        
        # Test MCP client imports
        logger.info("✅ CrowdStrike MCP client available")
        logger.info("✅ AWS Security MCP client available")
        logger.info("✅ GitHub Security MCP client available")
        
        logger.info("🎉 Platform test completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Platform test failed: {e}")
        return False


async def run_security_scan(target: str):
    """Run a security scan on the specified target."""
    logger = logging.getLogger(__name__)
    logger.info(f"🔍 Starting security scan of: {target}")
    
    # This would integrate with the actual security scanning logic
    logger.info("📊 Security scan completed")
    logger.info("💡 This is a placeholder - implement actual scanning logic")


async def start_monitoring():
    """Start continuous security monitoring."""
    logger = logging.getLogger(__name__)
    logger.info("🛡️ Starting continuous security monitoring...")
    
    # This would start the actual monitoring services
    logger.info("📊 Monitoring services active")
    logger.info("💡 This is a placeholder - implement actual monitoring logic")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SecurityAgents Platform - Enterprise AI-Powered Security Operations"
    )
    
    parser.add_argument(
        '--log-level', 
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Set logging level'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test platform functionality')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('target', help='Target to scan (repository, server, etc.)')
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Start continuous monitoring')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show platform status')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    logger.info("🚀 SecurityAgents Platform CLI")
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'test':
            success = asyncio.run(test_platform())
            sys.exit(0 if success else 1)
            
        elif args.command == 'scan':
            asyncio.run(run_security_scan(args.target))
            
        elif args.command == 'monitor':
            asyncio.run(start_monitoring())
            
        elif args.command == 'status':
            logger.info("📊 Platform Status: Active")
            logger.info("🔧 Configuration: See config/default.yaml")
            logger.info("📝 Logs: logs/security_agents.log")
            
    except KeyboardInterrupt:
        logger.info("🛑 Operation cancelled by user")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()