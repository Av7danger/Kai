# Document Management Feature - Quick Test Guide

## 🎯 The Document Management Feature is Now Working!

The document management system has been successfully implemented and is ready for use. Here's how to test it:

## 🚀 Quick Start

1. **Access the Web UI**: Open http://localhost:5000
2. **Navigate to Documents**: Click "Documents" in the navigation menu
3. **Upload a Document**: Click "Upload Document" button

## 📄 Test Document Available

I've created a sample bug bounty program document for testing:
- **File**: `sample_bbp_document.md`
- **Location**: Current directory
- **Content**: Complete bug bounty program with scope, targets, rewards, and contact info

## 🔧 Features to Test

### 1. Document Upload
- Upload the `sample_bbp_document.md` file
- Add description and tags
- Associate with a target (optional)

### 2. Document Parsing
- Click "Parse" on uploaded document
- View extracted information:
  - **URLs**: All web applications and endpoints
  - **Domains**: In-scope domains and subdomains
  - **Scope Information**: Program rules and guidelines
  - **Reward Information**: Payout structure
  - **Email Addresses**: Contact information

### 3. Target Extraction
- Click "Extract Targets" to automatically add domains to target list
- Extracted targets will include:
  - example.com and all subdomains
  - API endpoints
  - Web applications

### 4. Document Management
- View document details
- Download original files
- Delete documents
- Filter by target
- Export document list

## 🎯 Expected Parsing Results

From the sample document, the system should extract:

### Domains (12+ domains)
- example.com
- api.example.com
- mobile.example.com
- admin.example.com
- staging.example.com
- test.example.com
- dev.example.com
- mail.example.com
- blog.example.com
- shop.example.com
- secure.example.com
- vpn.example.com

### URLs (4+ URLs)
- https://example.com/app
- https://api.example.com/v1
- https://api.example.com/v2
- https://mobile.example.com/api
- https://bugbounty.example.com

### Email Addresses (3+ emails)
- security@example.com
- emergency-security@example.com
- security-team@example.com

### Scope Information
- In-scope domains section
- Out-of-scope section
- Program rules
- Testing guidelines

### Reward Information
- Critical: $5,000 - $15,000
- High: $1,000 - $5,000
- Medium: $200 - $1,000
- Low: $50 - $200

## 🛠️ Technical Implementation

The document management system includes:

### Backend Features
- File upload handling (supports .txt, .md, .pdf, .doc, .docx)
- Text extraction and parsing
- Database storage with metadata
- RESTful API endpoints
- Target auto-extraction

### Frontend Features
- Modern card-based document display
- Modal dialogs for parsing results
- Progress indicators
- Document statistics
- Bulk operations

### Database Schema
```sql
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    target_id INTEGER,
    name TEXT,
    description TEXT,
    file_type TEXT,
    file_path TEXT,
    file_size INTEGER,
    content_type TEXT,
    tags TEXT,
    scope_info TEXT,
    program_info TEXT,
    uploaded_at TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets (id)
)
```

## 🎮 Step-by-Step Testing

1. **Start the Web UI**: `python start_ui.py`
2. **Open Browser**: Navigate to http://localhost:5000
3. **Go to Documents**: Click "Documents" in navigation
4. **Upload Sample**: Click "Upload Document" and select `sample_bbp_document.md`
5. **Parse Document**: Click "Parse" button on the uploaded document
6. **Extract Targets**: Click "Extract Targets" to add domains to target list
7. **View Results**: Check the extracted information in modal dialogs

## 📊 Document Statistics

The dashboard shows:
- Total documents uploaded
- Number of targets with documents
- Documents containing scope information
- Documents containing program information

## ✅ Success Criteria

The feature is working correctly when you can:
- ✅ Upload documents successfully
- ✅ View document list with metadata
- ✅ Parse documents and extract information
- ✅ Automatically extract targets from scope
- ✅ Download original documents
- ✅ Delete documents
- ✅ View document statistics

## 🚀 Ready to Use!

The document management feature is fully functional and ready for real bug bounty program documents. You can now upload your actual program scope files, policy documents, and target lists to manage your bug bounty hunting workflow efficiently.

---

**Note**: The system supports various file formats and automatically extracts relevant information to help streamline your bug bounty research and target management.
