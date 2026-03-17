# Ay Fat ass  Web Application

A modern web application for managing security scanning projects with a clean, responsive interface built with Flask and SQLite.

## Features

- **Web Interface**: Clean, responsive web UI built with Flask and Bootstrap
- **Project Management**: Create, view, edit, and delete security scanning projects
- **SQLite Database**: Lightweight, file-based database - no external dependencies
- **Project Statistics**: View project details and statistics
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Modern UI**: Clean interface with Font Awesome icons and Bootstrap styling
- **RESTful API**: JSON API endpoints for programmatic access

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Run the Web Application

```bash
python run.py
```

### 2. Access the Web Interface

Open your browser and go to: `http://localhost:5000`

### 3. Create Your First Project

1. Click "New Project" button
2. Fill in the project details:
   - **Project Name**: A descriptive name
   - **Description**: Optional project description
   - **Zip File Path**: Path to your project's zip file
   - **Base Path**: Base directory for the project
   - **Status**: Active, Inactive, Archived, or Scanning

### 4. Manage Projects

- **View Projects**: See all your projects on the home page
- **Edit Projects**: Click "Edit" to modify project details
- **Delete Projects**: Click "Delete" to remove projects
- **View Details**: Click "View" to see project statistics and details

## Web Interface Features

### Project Management
- **Project Listing**: View all projects in a responsive card layout
- **Project Creation**: Simple form to create new projects
- **Project Editing**: Update project details and settings
- **Project Deletion**: Safe deletion with confirmation modal
- **Project Details**: View comprehensive project information and statistics

### User Interface
- **Responsive Design**: Works on all device sizes
- **Modern Styling**: Clean, professional appearance
- **Interactive Elements**: Hover effects, animations, and smooth transitions
- **Status Indicators**: Visual status badges for projects
- **Statistics Display**: Project statistics with color-coded metrics

### API Endpoints
- `GET /api/projects` - Get all projects as JSON
- `GET /` - Project listing page
- `GET /projects/new` - Create new project form
- `POST /projects/new` - Create new project
- `GET /projects/<id>` - View project details
- `GET /projects/<id>/edit` - Edit project form
- `POST /projects/<id>/edit` - Update project
- `POST /projects/<id>/delete` - Delete project

## Models

### Settings (AI Models)
- **model_name**: Name of the AI model
- **vendor**: Model provider (OpenAI, Anthropic, etc.)
- **api_key**: Authentication key
- **api_base_url**: Custom API endpoint
- **model_version**: Model version
- **max_tokens**: Maximum tokens per request
- **temperature**: Model temperature setting
- **timeout**: Request timeout
- **is_active**: Whether model is active

### Agent
- **name**: Agent name
- **version**: Agent version
- **description**: Agent description
- **system_prompt**: System-level prompt
- **task_prompt**: Task-specific prompt
- **is_active**: Whether agent is active

### Finding
- **file_path**: Path to vulnerable file
- **title**: Finding title
- **description**: Detailed description
- **recommendation**: Fix recommendation
- **severity**: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **status**: Finding status (OPEN, IN_PROGRESS, RESOLVED, etc.)
- **code_snippet**: Vulnerable code
- **line_number**: Primary line number
- **confidence_score**: AI confidence (0.0-1.0)
- **tags**: Categorization tags
- **cwe_id**: Common Weakness Enumeration ID
- **owasp_category**: OWASP category
- **impacted_files**: JSON array of affected files with line numbers

### Project
- **name**: Project name
- **description**: Project description
- **zip_file_path**: Path to project zip file
- **base_path**: Project base directory
- **status**: Project status (ACTIVE, INACTIVE, ARCHIVED, SCANNING)
- **language**: Primary programming language
- **framework**: Framework used
- **version**: Project version
- **scan_config**: Custom scan configuration
- **exclude_patterns**: Files/folders to exclude
- **include_patterns**: Files/folders to include
- **total_files**: Total file count
- **total_lines**: Total line count
- **findings_count**: Total findings count

## ORM Methods

### Generic CRUD Operations
```python
# Create
instance = orm.create(session, ModelClass, **kwargs)

# Read
instance = orm.get_by_id(session, ModelClass, id)
instance = orm.get_by_uuid(session, ModelClass, uuid)
instances = orm.get_all(session, ModelClass, limit=10, offset=0)

# Update
updated = orm.update(session, instance, field=new_value)

# Delete
success = orm.delete(session, instance)
success = orm.delete_by_id(session, ModelClass, id)
```

### Query Operations
```python
# Filter
results = orm.filter_by(session, ModelClass, field=value)
result = orm.filter_one(session, ModelClass, field=value)

# Count
count = orm.count(session, ModelClass, field=value)

# Search
findings = orm.search_findings(session, "SQL injection", project_id)
```

### Specialized Methods
```python
# Get active models/agents
models = orm.get_active_models(session)
agents = orm.get_active_agents(session)

# Get project findings
findings = orm.get_project_findings(session, project_id, severity="HIGH")

# Get statistics
stats = orm.get_project_stats(session, project_id)
global_stats = orm.get_global_stats(session)

# Health check
is_healthy = orm.health_check()
```

## Database

### SQLite Only
This application uses SQLite exclusively for simplicity and portability:

- **No External Dependencies**: No need for database servers
- **File-Based**: Database stored in `app.db` file
- **Automatic Setup**: Database and tables created automatically
- **Portable**: Easy to backup and move between systems

### Database Features
- **Automatic Directory Creation**: Creates database directory if needed
- **Path Resolution**: Handles both absolute and relative paths
- **Connection Timeout**: 30-second timeout for database operations
- **Thread Safety**: Properly configured for web applications

## Environment Configurations

The system comes with pre-configured environments:

- **development**: SQLite with echo enabled (`dev.db`)
- **testing**: In-memory SQLite for testing
- **production**: SQLite with optimized settings (`app.db`)

## Error Handling

All ORM methods include comprehensive error handling and logging:

```python
try:
    with orm.get_session() as session:
        # Your operations here
        pass
except Exception as e:
    print(f"Database error: {e}")
```

## Examples

See `example_usage.py` for comprehensive usage examples including:
- Basic CRUD operations
- Multi-database configuration
- Complex queries and relationships
- Statistics and analytics
- Search functionality

## Dependencies

- SQLAlchemy >= 1.4.0 (Database ORM)
- Alembic >= 1.8.0 (Database migrations)
- Flask >= 2.3.0 (Web framework)

## License

MIT License