import json
import os
import logging
from dotenv import load_dotenv
from crypto_manager import generate_signature

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

def analyze_posture(evidence_file='cloud_evidence.json'):
    """
    Reads the extraction evidence and uses GenAI to identify vulnerabilities 
    and provide a remediation command.
    """
    logger.info("Analyzing security posture...")
    
    try:
        with open(evidence_file, 'r') as f:
            evidence = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read evidence file: {e}")
        return {
            "risk_level": "Unknown",
            "explanation": f"Failed to read evidence: {str(e)}",
            "remediation_command": ""
        }

    system_prompt = """You are an expert Cloud Security Auditor.
Analyze the following AWS S3 bucket security configuration represented in JSON format.
Your task is to identify if the bucket is publicly accessible or has any other vulnerabilities.
Return ONLY a valid JSON object with EXACTLY the following keys:
- "risk_level": "High", "Medium", or "Low"
- "explanation": "A human-readable explanation of the vulnerabilities found."
- "remediation_command": "The exact AWS CLI command(s) to fix the vulnerability (e.g., block public access)."
Do not include markdown blocks or any other text outside the JSON.
"""
    prompt = f"{system_prompt}\nEvidence:\n{json.dumps(evidence, indent=2)}\n"

    # Try OCI Generative AI first
    oci_profile = os.environ.get("OCI_CONFIG_PROFILE")
    oci_compartment = os.environ.get("OCI_COMPARTMENT_OCID")
    
    if oci_profile and oci_compartment and oci_compartment != "ocid1.compartment.oc1..exampleuniqueID":
        try:
            import oci
            logger.info("Using OCI Generative AI...")
            config = oci.config.from_file(profile_name=oci_profile)
            generative_ai_inference_client = oci.generative_ai_inference.GenerativeAiInferenceClient(config=config)
            
            llm_inference_request = oci.generative_ai_inference.models.CohereLlmInferenceRequest()
            llm_inference_request.prompt = prompt
            llm_inference_request.max_tokens = 500
            llm_inference_request.temperature = 0.1
            llm_inference_request.frequency_penalty = 0
            llm_inference_request.top_p = 0.75

            generate_text_detail = oci.generative_ai_inference.models.GenerateTextDetails()
            generate_text_detail.serving_mode = oci.generative_ai_inference.models.OnDemandServingMode(
                model_id="cohere.command"
            )
            generate_text_detail.compartment_id = oci_compartment
            generate_text_detail.inference_request = llm_inference_request

            generate_text_response = generative_ai_inference_client.generate_text(generate_text_detail)
            response_text = generate_text_response.data.inference_response.generated_texts[0].text
            
            try:
                return parse_json_response(response_text)
            except json.JSONDecodeError:
                pass # Fallback if OCI returned invalid JSON
                
        except Exception as e:
            logger.warning(f"OCI Generative AI failed or not configured correctly: {e}. Falling back...")

    # Fallback to Google Gemini
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    if gemini_api_key and gemini_api_key != "your_gemini_api_key_here":
        try:
            import google.generativeai as genai
            logger.info("Using Google Gemini API as fallback...")
            genai.configure(api_key=gemini_api_key)
            model = genai.GenerativeModel('gemini-1.5-pro')
            response = model.generate_content(prompt)
            return parse_json_response(response.text)
        except Exception as e:
            logger.warning(f"Google Gemini failed or not configured correctly: {e}. Falling back to Groq...")

    # Fallback to Groq (Llama 3)
    groq_api_key = os.environ.get("GROQ_API_KEY")
    if groq_api_key and groq_api_key != "your_groq_api_key_here":
        try:
            from groq import Groq
            logger.info("Using Groq (Llama 3) API as fallback...")
            client = Groq(api_key=groq_api_key)
            
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama3-70b-8192",
                temperature=0.1,
            )
            return parse_json_response(chat_completion.choices[0].message.content)
        except Exception as e:
            logger.warning(f"Groq failed or not configured correctly: {e}. Falling back to mock...")

    # Fallback for prototype running without API keys
    logger.info("Using Mock AI Response for local prototype testing without keys...")
    
    bucket_name = evidence.get("bucket_name", "test-bucket")
    
    # Check Public Access
    is_public = False
    grants = evidence.get("grants", [])
    for grant in grants:
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
            is_public = True
            break
            
    # Check Encryption
    encryption = evidence.get("server_side_encryption")
    
    # Check MFA Delete
    versioning = evidence.get("versioning", {})
    mfa_delete = versioning.get("MFADelete") == "Disabled"
            
    if is_public:
        assessment = {
            "risk_level": "High",
            "explanation": "The S3 bucket ACL grants public 'AllUsers' group read/write access. This allows any unauthenticated user on the internet to access the bucket's objects, posing a severe data breach risk.",
            "remediation_command": f"aws --endpoint-url=http://localhost:4566 s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        }
    elif encryption is None:
        assessment = {
            "risk_level": "High",
            "explanation": "The S3 bucket does not have Server-Side Encryption (SSE) configured by default. Data at rest is vulnerable and not aligned with compliance standards.",
            "remediation_command": f"aws --endpoint-url=http://localhost:4566 s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
        }
    elif mfa_delete:
         assessment = {
            "risk_level": "Medium",
            "explanation": "The S3 bucket has versioning enabled but MFA Delete is disabled. This leaves the bucket vulnerable to unauthorized permanent deletion of object versions or changes to the versioning state.",
            "remediation_command": f"aws --endpoint-url=http://localhost:4566 s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa 'arn:aws:iam::123456789012:mfa/root-account-mfa-device 123456'"
        }
    else:
        assessment = {
            "risk_level": "Low",
            "explanation": "The S3 bucket configuration appears secure based on the extracted metadata. No open public ACLs, missing encryption, or disabled MFA-Delete configurations were found.",
            "remediation_command": "# No critical access/configuration issues found."
        }
        
    assessment["blast_radius"] = evidence.get("blast_radius", {})
    
    # ---------------------------------------------------------
    # The Critic LLM Call
    # ---------------------------------------------------------
    logger.info("Engaging Critic LLM for Zero-Trust Validation...")
    
    critic_prompt = f"""You are an automated safety validation tool. Analyze this AWS CLI command. Does it pose a risk of deleting data or causing an irreversible outage? Return a JSON with 'is_safe' (boolean) and 'critic_reason' (string).
    Command: {assessment['remediation_command']}
    """
    
    is_safe = True
    critic_reason = "Command validated locally. The script only updates resource security configurations and does not contain destructive actions."
    
    # Attempt to use Groq Critic if available 
    if groq_api_key and groq_api_key != "your_groq_api_key_here":
        try:
            from groq import Groq
            client = Groq(api_key=groq_api_key)
            chat_completion = client.chat.completions.create(
                messages=[{"role": "user", "content": critic_prompt}],
                model="llama3-70b-8192",
                temperature=0.1,
            )
            critic_response = parse_json_response(chat_completion.choices[0].message.content)
            is_safe = critic_response.get("is_safe", True)
            critic_reason = critic_response.get("critic_reason", "Groq Critic Validated.")
        except Exception as e:
            logger.warning(f"Groq Critic failed: {e}. Falling back to local regex critic.")
            if "delete" in assessment["remediation_command"].lower() and "mfadelete=enabled" not in assessment["remediation_command"].lower():
                is_safe = False
                critic_reason = "Command rejected by local regex. Destructive string detected."
    else:
        # Local mock critic
        if "delete" in assessment["remediation_command"].lower() and "mfadelete=enabled" not in assessment["remediation_command"].lower():
            is_safe = False
            critic_reason = "Command rejected by local regex. Destructive string detected."
        
    assessment["critic_validation"] = {
        "is_safe": is_safe,
        "critic_reason": critic_reason
    }
    
    # ---------------------------------------------------------
    # Zero-Trust Cryptographic Signing
    # ---------------------------------------------------------
    if is_safe:
        logger.info("Critic approved safe execution. Generating cryptographic signature bounds.")
        assessment["cryptographic_signature"] = generate_signature(assessment["remediation_command"])
    else:
        logger.warning("Critic defined script as UNSAFE. Cryptographic signature withheld.")
        assessment["cryptographic_signature"] = "UNSIGNED_UNSAFE_SCRIPT"
        
    return assessment

def parse_json_response(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return json.loads(text.strip())

if __name__ == "__main__":
    print(json.dumps(analyze_posture(), indent=2))
