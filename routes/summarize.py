"""Summarize findings route"""
from flask_login import login_required, current_user
from flask import render_template, request, flash
from routes import summarize_bp
from utils.flask_helpers import get_orm_instance
from db.models import Project, AIModel, Finding
from sqlalchemy.orm import joinedload
import os
import logging

logger = logging.getLogger(__name__)


@summarize_bp.route('/summarize', methods=['GET', 'POST'])
@login_required
def summarize_page():
    """Summarize filtered findings using a selected AI model via LiteLLM."""
    try:
        orm = get_orm_instance()
        with orm.get_session() as session:
            if current_user.is_admin:
                projects = orm.get_all(session, Project)
            else:
                projects = session.query(Project).filter(Project.owner_id == current_user.id).all()
            models = orm.get_all(session, AIModel)

            if request.method == 'GET':
                return render_template('summarize.html', projects=projects, models=models, summary_text=None)

            # POST: run summarization
            project_id = request.form.get('project_id')
            severity = request.form.get('severity')
            status = request.form.get('status')
            search = request.form.get('search')
            model_id = request.form.get('model_id')

            if not model_id:
                flash('Please select an AI model to summarize.', 'error')
                return render_template('summarize.html', projects=projects, models=models, summary_text=None)

            model = orm.get_by_id(session, AIModel, int(model_id))
            if not model:
                flash('Selected AI model not found.', 'error')
                return render_template('summarize.html', projects=projects, models=models, summary_text=None)

            # Query findings per filters
            query = session.query(Finding).options(joinedload(Finding.project))
            if project_id:
                query = query.filter(Finding.project_id == project_id)
            if severity:
                query = query.filter(Finding.severity == severity)
            if status:
                query = query.filter(Finding.status == status)
            if search:
                query = query.filter(
                    Finding.title.ilike(f"%{search}%") |
                    Finding.description.ilike(f"%{search}%")
                )
            findings = query.order_by(Finding.created_at.desc()).all()

            # Build a concise context for the LLM
            def safe_val(v):
                try:
                    return v.value  # enums
                except Exception:
                    return str(v)

            items = []
            for f in findings[:200]:  # cap to avoid excessive prompt size
                items.append(
                    {
                        'id': f.id,
                        'title': f.title,
                        'severity': safe_val(getattr(f, 'severity', '')),
                        'status': safe_val(getattr(f, 'status', '')),
                        'file_path': getattr(f, 'file_path', None) or '',
                        'project': f.project.name if getattr(f, 'project', None) else ''
                    }
                )

            total_findings = len(findings)
            by_severity = {}
            for it in items:
                sev = (it['severity'] or 'unknown').lower()
                by_severity[sev] = by_severity.get(sev, 0) + 1

            # Prompt
            summary_prompt = (
                "You are a security auditor tasked with summarizing the current security review progress based on filtered findings from an automated scan.\n"
                "Your summary should:\n"
                "1) Give an overview of project coverage and highlight which areas/directories/files have already been checked and generated findings.\n"
                "2) Provide the total number of findings and a breakdown by severity level.\n"
                "3) Highlight the files, directories, or components where issues were found, giving an idea of codebase areas that have been examined so far (e.g. 'api/', 'controllers/', specific files).\n"
                "4) If possible, infer areas not yet checked or suggest parts of the codebase that could be next priorities for review.\n"
                "5) End with succinct, actionable bullet points about progress, coverage, and any obvious next steps or gaps observed.\n"
                "Keep your response clear and concise (250-300 words).\n\n"
                f"Total findings: {total_findings}\n"
                f"Counts by severity: {by_severity}\n"
                "Sample of checked findings (id, severity, status, file, title):\n" +
                "\n".join([
                    f"- {it['id']} | {it['severity']} | {it['status']} | {it['file_path']} | {it['title']}" for it in items[:50]
                ])
            )

            # Prepare LiteLLM call using model vendor/key
            import litellm
            from litellm import completion

            vendor_mapping = {
                'openai': 'openai',
                'anthropic': 'anthropic',
                'gemini': 'google',
                'xai': 'xai',
                'deepseek': 'deepseek',
                'larprouter': 'openai'
            }
            provider = vendor_mapping.get(model.vendor.lower())
            if not provider:
                flash(f'Unsupported vendor: {model.vendor}', 'error')
                return render_template('summarize.html', projects=projects, models=models, summary_text=None)

            # Set API key in env for this request
            env_var = f"{model.vendor.upper()}_API_KEY"
            original_key = os.environ.get(env_var)
            os.environ[env_var] = model.api_key or ''
            try:
                full_model_name = f"gemini/{model.model_name}" if provider == 'google' else f"{provider}/{model.model_name}"
                options = {"model": full_model_name}
                if model.vendor.lower() == "larprouter":
                    from utils.ai_models_utils import model_completion_options
                    options = model_completion_options(model)
                    options.update(timeout=45, num_retries=0)
                else:
                    options["timeout"] = 30
                resp = completion(
                    **options,
                    messages=[{"role": "user", "content": summary_prompt}],
                    max_tokens=2048 if model.vendor.lower() == "larprouter" else 500,
                    temperature=0.2,
                )
                summary_text = resp.choices[0].message.content if getattr(resp, 'choices', None) else 'No response.'
            except Exception as e:
                logger.error(f"Summarization failed: {e}")
                flash('Summarization failed. Check model credentials and try again.', 'error')
                summary_text = None
            finally:
                if original_key is not None:
                    os.environ[env_var] = original_key
                else:
                    os.environ.pop(env_var, None)

            return render_template(
                'summarize.html',
                projects=projects,
                models=models,
                summary_text=summary_text,
                selected_project_id=project_id,
                selected_severity=severity,
                selected_status=status,
                search=search,
                selected_model_id=model_id,
            )
    except Exception as e:
        logger.error(f"Error in summarize page: {e}")
        flash('Error generating summary', 'error')
        orm = get_orm_instance()
        with orm.get_session() as session:
            return render_template('summarize.html', projects=(orm.get_all(session, Project) if current_user.is_admin else session.query(Project).filter(Project.owner_id == current_user.id).all()), models=orm.get_all(session, AIModel), summary_text=None)

