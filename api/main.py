from fastapi import FastAPI, Depends
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import requests
from database import SessionLocal, CVE

#Create FastAPI instance
api = FastAPI()

#CORS Middleware: Allow localhost and 127.0.0.1
api.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8080", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

#NVD API URL
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#Main Endpoint: Return CVEs from DB or NVD API
@api.get("/cves/list")
def fetch_cves(
    cve_id: str = None,
    year: int = None,
    score: float = None,
    db: Session = Depends(get_db)
):
    #Search by CVE ID in Database
    if cve_id: 
        cve = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if cve:
            return jsonable_encoder({
                "cve_id": cve.cve_id,
                "identifier": cve.description,
                "published_date": "N/A",
                "last_modified_date": "N/A",
                "status": "N/A"
            })

    #Fetch from NVD API
    params = {"resultsPerPage": 10}
    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000Z"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.000Z"

    response = requests.get(api_url, params=params).json()

    new_cve_count = 0
    for item in response.get("vulnerabilities", []):
        cve_data = item["cve"]
        descriptions = cve_data.get("descriptions", [])
        published_date = cve_data.get("published", "N/A")
        last_modified_date = cve_data.get("lastModified", "N/A")

        description_value = next(
            (desc["value"] for desc in descriptions if desc.get("lang") == "en"), "No description available"
        )

        #Get CVSS Score
        cvss_score = cve_data.get("metrics", {}).get("cvssMetricV3", [{}])[0].get("cvssData", {}).get("baseScore")

        #Save only new CVEs to Database
        existing_cve = db.query(CVE).filter(CVE.cve_id == cve_data["id"]).first()
        if not existing_cve:
            new_cve = CVE(
                cve_id=cve_data["id"],
                description=description_value,
                cvss_score=cvss_score
            )
            db.add(new_cve)
            new_cve_count += 1

    if new_cve_count > 0:
        db.commit()

    #Query Database with Filters
    query = db.query(CVE)
    if year:
        query = query.filter(CVE.cve_id.startswith(f"CVE-{year}-"))
    if score:
        query = query.filter(CVE.cvss_score >= score)

    results = query.limit(10).all()

    #Return Proper JSON with Real Data
    return jsonable_encoder([
        {
            "cve_id": c.cve_id,
            "identifier": c.description,
            "published_date": published_date,
            "last_modified_date": last_modified_date,
            "status": "Available"
        }
        for c in results
    ])