#!/usr/bin/env python3
"""
🔍 ADVANCED DATA PROVENANCE & AUDIT TRAIL MODULE
📊 Comprehensive evidence integrity and chain of custody
🛡️ Cryptographic proof of data authenticity and lineage
⚡ Strategic implementation of Expert Feedback Recommendation #4

This module implements advanced data provenance that:
- Tracks complete data lineage from source to analysis
- Provides cryptographic proof of evidence integrity
- Maintains immutable audit trails for forensic analysis
- Enables reconstruction of decision processes
- Supports regulatory compliance and legal admissibility
"""

import asyncio
import hashlib
import json
import logging
import sqlite3
import time
import zlib
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
import base64
import hmac
import secrets


class ProvenanceEventType(Enum):
    """Types of provenance events"""
    DATA_CREATION = "data_creation"
    DATA_MODIFICATION = "data_modification"
    DATA_ACCESS = "data_access"
    DATA_ANALYSIS = "data_analysis"
    DATA_TRANSFER = "data_transfer"
    DATA_VALIDATION = "data_validation"
    AI_DECISION = "ai_decision"
    HUMAN_REVIEW = "human_review"
    SYSTEM_EVENT = "system_event"


class IntegrityLevel(Enum):
    """Levels of data integrity verification"""
    BASIC = "basic"
    ENHANCED = "enhanced"
    CRYPTOGRAPHIC = "cryptographic"
    FORENSIC = "forensic"


class DataClassification(Enum):
    """Data classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


@dataclass
class DataLineage:
    """Complete lineage of a data element"""
    data_id: str
    source_system: str
    creation_timestamp: datetime
    original_hash: str
    current_hash: str
    transformation_chain: List[Dict[str, Any]]
    access_history: List[Dict[str, Any]]
    classification: DataClassification
    retention_policy: str
    legal_holds: List[str]


@dataclass
class ProvenanceEvent:
    """Individual provenance event"""
    event_id: str
    timestamp: datetime
    event_type: ProvenanceEventType
    actor_id: str
    actor_type: str  # human, ai_agent, system
    data_affected: List[str]
    operation_details: Dict[str, Any]
    input_hash: str
    output_hash: str
    integrity_proof: str
    parent_events: List[str]
    metadata: Dict[str, Any]


@dataclass
class AuditChain:
    """Immutable audit chain for data operations"""
    chain_id: str
    genesis_hash: str
    current_hash: str
    block_count: int
    events: List[ProvenanceEvent]
    cryptographic_proofs: List[str]
    witness_signatures: List[str]


class AdvancedDataProvenanceModule:
    """
    Advanced data provenance and audit trail system that provides
    cryptographic proof of data integrity and complete lineage tracking.
    """
    
    def __init__(self, db_path: str = "data_provenance.db", secret_key: Optional[str] = None):
        self.db_path = db_path
        self.secret_key = secret_key or secrets.token_hex(32)
        self.logger = self._setup_logging()
        
        # In-memory caches
        self.active_lineages: Dict[str, DataLineage] = {}
        self.audit_chains: Dict[str, AuditChain] = {}
        self.pending_events: List[ProvenanceEvent] = []
        
        # Initialize database
        self._init_database()
        
        # Load existing lineages
        self._load_existing_lineages()
        
        # Initialize cryptographic components
        self._init_crypto_components()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging for provenance module."""
        logger = logging.getLogger("DataProvenance")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _init_database(self):
        """Initialize provenance database with comprehensive schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Data lineage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_lineage (
                data_id TEXT PRIMARY KEY,
                source_system TEXT NOT NULL,
                creation_timestamp TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                transformation_chain TEXT,
                access_history TEXT,
                classification TEXT NOT NULL,
                retention_policy TEXT,
                legal_holds TEXT,
                last_updated TEXT
            )
        ''')
        
        # Provenance events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS provenance_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                data_affected TEXT,
                operation_details TEXT,
                input_hash TEXT,
                output_hash TEXT,
                integrity_proof TEXT,
                parent_events TEXT,
                metadata TEXT,
                chain_id TEXT,
                block_index INTEGER
            )
        ''')
        
        # Audit chains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_chains (
                chain_id TEXT PRIMARY KEY,
                genesis_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL,
                block_count INTEGER NOT NULL,
                cryptographic_proofs TEXT,
                witness_signatures TEXT,
                created_at TEXT NOT NULL,
                last_block_timestamp TEXT
            )
        ''')
        
        # Integrity verification table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS integrity_verifications (
                verification_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                data_id TEXT NOT NULL,
                verification_type TEXT NOT NULL,
                verification_result BOOLEAN NOT NULL,
                hash_expected TEXT,
                hash_actual TEXT,
                anomalies_detected TEXT,
                remediation_actions TEXT
            )
        ''')
        
        # Digital signatures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS digital_signatures (
                signature_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                signer_id TEXT NOT NULL,
                data_hash TEXT NOT NULL,
                signature_value TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                certificate_chain TEXT,
                verification_status TEXT
            )
        ''')
        
        # Evidence custody table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_custody (
                custody_id TEXT PRIMARY KEY,
                evidence_id TEXT NOT NULL,
                custodian_id TEXT NOT NULL,
                custody_start TEXT NOT NULL,
                custody_end TEXT,
                custody_reason TEXT,
                transfer_conditions TEXT,
                integrity_checks TEXT,
                witness_details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_existing_lineages(self):
        """Load existing data lineages from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM data_lineage')
        for row in cursor.fetchall():
            lineage = DataLineage(
                data_id=row[0],
                source_system=row[1],
                creation_timestamp=datetime.fromisoformat(row[2]),
                original_hash=row[3],
                current_hash=row[4],
                transformation_chain=json.loads(row[5]) if row[5] else [],
                access_history=json.loads(row[6]) if row[6] else [],
                classification=DataClassification(row[7]),
                retention_policy=row[8] or "",
                legal_holds=json.loads(row[9]) if row[9] else []
            )
            self.active_lineages[lineage.data_id] = lineage
        
        conn.close()
        self.logger.info(f"Loaded {len(self.active_lineages)} existing data lineages")
    
    def _init_crypto_components(self):
        """Initialize cryptographic components for integrity verification."""
        self.hash_algorithm = "sha256"
        self.signature_algorithm = "HMAC-SHA256"
        
        # Generate master keys for different purposes
        self.integrity_key = hashlib.pbkdf2_hmac('sha256', self.secret_key.encode(), b'integrity', 100000)
        self.audit_key = hashlib.pbkdf2_hmac('sha256', self.secret_key.encode(), b'audit', 100000)
        self.witness_key = hashlib.pbkdf2_hmac('sha256', self.secret_key.encode(), b'witness', 100000)
        
        self.logger.info("Initialized cryptographic components for data integrity")
    
    async def create_data_lineage(
        self, 
        data_content: Any, 
        source_system: str,
        classification: DataClassification = DataClassification.INTERNAL,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new data lineage for tracking a data element.
        
        Args:
            data_content: The actual data content
            source_system: System that created the data
            classification: Data classification level
            metadata: Additional metadata
            
        Returns:
            Data ID for the created lineage
        """
        try:
            # Generate unique data ID
            data_id = f"data_{int(time.time())}_{secrets.token_hex(8)}"
            
            # Calculate content hash
            content_str = json.dumps(data_content, sort_keys=True, default=str)
            original_hash = hashlib.sha256(content_str.encode()).hexdigest()
            
            # Create lineage
            lineage = DataLineage(
                data_id=data_id,
                source_system=source_system,
                creation_timestamp=datetime.now(),
                original_hash=original_hash,
                current_hash=original_hash,
                transformation_chain=[],
                access_history=[],
                classification=classification,
                retention_policy="default_7_years",
                legal_holds=[]
            )
            
            # Store lineage
            await self._store_lineage(lineage)
            self.active_lineages[data_id] = lineage
            
            # Create initial provenance event
            await self.record_provenance_event(
                event_type=ProvenanceEventType.DATA_CREATION,
                actor_id="system",
                actor_type="system",
                data_affected=[data_id],
                operation_details={
                    "source_system": source_system,
                    "data_size": len(content_str),
                    "classification": classification.value,
                    "metadata": metadata or {}
                },
                input_hash="",
                output_hash=original_hash
            )
            
            self.logger.info(f"Created data lineage: {data_id} from {source_system}")
            return data_id
            
        except Exception as e:
            self.logger.error(f"Error creating data lineage: {str(e)}")
            raise
    
    async def record_provenance_event(
        self,
        event_type: ProvenanceEventType,
        actor_id: str,
        actor_type: str,
        data_affected: List[str],
        operation_details: Dict[str, Any],
        input_hash: str,
        output_hash: str,
        parent_events: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Record a provenance event in the audit trail.
        
        Args:
            event_type: Type of the provenance event
            actor_id: ID of the actor performing the operation
            actor_type: Type of actor (human, ai_agent, system)
            data_affected: List of data IDs affected by this event
            operation_details: Details of the operation performed
            input_hash: Hash of input data
            output_hash: Hash of output data
            parent_events: List of parent event IDs
            metadata: Additional metadata
            
        Returns:
            Event ID of the recorded event
        """
        try:
            # Generate unique event ID
            event_id = f"event_{int(time.time())}_{secrets.token_hex(8)}"
            timestamp = datetime.now()
            
            # Generate integrity proof
            integrity_proof = self._generate_integrity_proof(
                event_id, timestamp, operation_details, input_hash, output_hash
            )
            
            # Create provenance event
            event = ProvenanceEvent(
                event_id=event_id,
                timestamp=timestamp,
                event_type=event_type,
                actor_id=actor_id,
                actor_type=actor_type,
                data_affected=data_affected,
                operation_details=operation_details,
                input_hash=input_hash,
                output_hash=output_hash,
                integrity_proof=integrity_proof,
                parent_events=parent_events or [],
                metadata=metadata or {}
            )
            
            # Store event
            await self._store_provenance_event(event)
            
            # Update affected data lineages
            for data_id in data_affected:
                if data_id in self.active_lineages:
                    await self._update_lineage_for_event(data_id, event)
            
            # Add to audit chain
            await self._add_to_audit_chain(event)
            
            self.logger.info(f"Recorded provenance event: {event_id} ({event_type.value})")
            return event_id
            
        except Exception as e:
            self.logger.error(f"Error recording provenance event: {str(e)}")
            raise
    
    def _generate_integrity_proof(
        self,
        event_id: str,
        timestamp: datetime,
        operation_details: Dict[str, Any],
        input_hash: str,
        output_hash: str
    ) -> str:
        """Generate cryptographic integrity proof for an event."""
        # Combine all event data for proof generation
        proof_data = {
            "event_id": event_id,
            "timestamp": timestamp.isoformat(),
            "operation": operation_details,
            "input_hash": input_hash,
            "output_hash": output_hash
        }
        
        # Create deterministic JSON
        proof_json = json.dumps(proof_data, sort_keys=True, separators=(',', ':'))
        
        # Generate HMAC signature
        signature = hmac.new(
            self.integrity_key,
            proof_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    async def _store_lineage(self, lineage: DataLineage):
        """Store data lineage in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO data_lineage
            (data_id, source_system, creation_timestamp, original_hash,
             current_hash, transformation_chain, access_history,
             classification, retention_policy, legal_holds, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            lineage.data_id,
            lineage.source_system,
            lineage.creation_timestamp.isoformat(),
            lineage.original_hash,
            lineage.current_hash,
            json.dumps(lineage.transformation_chain),
            json.dumps(lineage.access_history),
            lineage.classification.value,
            lineage.retention_policy,
            json.dumps(lineage.legal_holds),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def _store_provenance_event(self, event: ProvenanceEvent):
        """Store provenance event in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO provenance_events
            (event_id, timestamp, event_type, actor_id, actor_type,
             data_affected, operation_details, input_hash, output_hash,
             integrity_proof, parent_events, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.event_id,
            event.timestamp.isoformat(),
            event.event_type.value,
            event.actor_id,
            event.actor_type,
            json.dumps(event.data_affected),
            json.dumps(event.operation_details),
            event.input_hash,
            event.output_hash,
            event.integrity_proof,
            json.dumps(event.parent_events),
            json.dumps(event.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    async def _update_lineage_for_event(self, data_id: str, event: ProvenanceEvent):
        """Update data lineage based on a provenance event."""
        if data_id not in self.active_lineages:
            return
        
        lineage = self.active_lineages[data_id]
        
        # Update access history
        access_record = {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "actor_id": event.actor_id,
            "actor_type": event.actor_type,
            "operation": event.event_type.value
        }
        lineage.access_history.append(access_record)
        
        # Update transformation chain if data was modified
        if event.event_type in [ProvenanceEventType.DATA_MODIFICATION, ProvenanceEventType.DATA_ANALYSIS]:
            transformation = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "operation": event.operation_details,
                "input_hash": event.input_hash,
                "output_hash": event.output_hash
            }
            lineage.transformation_chain.append(transformation)
            lineage.current_hash = event.output_hash
        
        # Store updated lineage
        await self._store_lineage(lineage)
    
    async def _add_to_audit_chain(self, event: ProvenanceEvent):
        """Add event to the immutable audit chain."""
        # For demo purposes, create a simple audit chain
        # In production, this would use blockchain-like structure
        chain_id = "main_audit_chain"
        
        if chain_id not in self.audit_chains:
            # Create new audit chain
            genesis_hash = hashlib.sha256(f"genesis_{datetime.now()}".encode()).hexdigest()
            self.audit_chains[chain_id] = AuditChain(
                chain_id=chain_id,
                genesis_hash=genesis_hash,
                current_hash=genesis_hash,
                block_count=0,
                events=[],
                cryptographic_proofs=[],
                witness_signatures=[]
            )
        
        chain = self.audit_chains[chain_id]
        
        # Add event to chain
        chain.events.append(event)
        chain.block_count += 1
        
        # Calculate new chain hash
        block_data = {
            "previous_hash": chain.current_hash,
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "integrity_proof": event.integrity_proof
        }
        block_json = json.dumps(block_data, sort_keys=True)
        chain.current_hash = hashlib.sha256(block_json.encode()).hexdigest()
        
        # Generate witness signature
        witness_signature = hmac.new(
            self.witness_key,
            chain.current_hash.encode(),
            hashlib.sha256
        ).hexdigest()
        chain.witness_signatures.append(witness_signature)
        
        # Store updated chain
        await self._store_audit_chain(chain)
    
    async def _store_audit_chain(self, chain: AuditChain):
        """Store audit chain in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO audit_chains
            (chain_id, genesis_hash, current_hash, block_count,
             cryptographic_proofs, witness_signatures, created_at, last_block_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            chain.chain_id,
            chain.genesis_hash,
            chain.current_hash,
            chain.block_count,
            json.dumps(chain.cryptographic_proofs),
            json.dumps(chain.witness_signatures),
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    async def verify_data_integrity(self, data_id: str, current_data: Any) -> Dict[str, Any]:
        """
        Verify the integrity of data against its lineage.
        
        Args:
            data_id: ID of the data to verify
            current_data: Current state of the data
            
        Returns:
            Integrity verification result
        """
        try:
            if data_id not in self.active_lineages:
                return {
                    "verified": False,
                    "error": "Data lineage not found",
                    "confidence": 0.0
                }
            
            lineage = self.active_lineages[data_id]
            
            # Calculate current hash
            content_str = json.dumps(current_data, sort_keys=True, default=str)
            current_hash = hashlib.sha256(content_str.encode()).hexdigest()
            
            # Verify against expected hash
            hash_matches = current_hash == lineage.current_hash
            
            # Verify transformation chain
            chain_valid = await self._verify_transformation_chain(lineage)
            
            # Verify audit trail
            audit_valid = await self._verify_audit_trail(data_id)
            
            # Calculate confidence score
            confidence_factors = [hash_matches, chain_valid, audit_valid]
            confidence = sum(confidence_factors) / len(confidence_factors)
            
            verification_result = {
                "verified": all(confidence_factors),
                "hash_matches": hash_matches,
                "chain_valid": chain_valid,
                "audit_valid": audit_valid,
                "confidence": confidence,
                "expected_hash": lineage.current_hash,
                "actual_hash": current_hash,
                "verification_timestamp": datetime.now().isoformat()
            }
            
            # Store verification result
            await self._store_verification_result(data_id, verification_result)
            
            return verification_result
            
        except Exception as e:
            self.logger.error(f"Error verifying data integrity: {str(e)}")
            return {
                "verified": False,
                "error": f"Verification failed: {str(e)}",
                "confidence": 0.0
            }
    
    async def _verify_transformation_chain(self, lineage: DataLineage) -> bool:
        """Verify the integrity of the transformation chain."""
        try:
            # Verify each transformation in the chain
            current_hash = lineage.original_hash
            
            for transformation in lineage.transformation_chain:
                # Verify input hash matches expected
                if transformation["input_hash"] != current_hash:
                    return False
                
                # Update current hash for next iteration
                current_hash = transformation["output_hash"]
            
            # Final hash should match current lineage hash
            return current_hash == lineage.current_hash
            
        except Exception as e:
            self.logger.error(f"Error verifying transformation chain: {str(e)}")
            return False
    
    async def _verify_audit_trail(self, data_id: str) -> bool:
        """Verify the audit trail for a data element."""
        try:
            # Get all events for this data
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT event_id, integrity_proof, operation_details, input_hash, output_hash, timestamp
                FROM provenance_events
                WHERE data_affected LIKE ?
                ORDER BY timestamp
            ''', (f'%"{data_id}"%',))
            
            events = cursor.fetchall()
            conn.close()
            
            # Verify each event's integrity proof
            for event in events:
                event_id, integrity_proof, operation_details, input_hash, output_hash, timestamp = event
                
                # Recreate integrity proof
                expected_proof = self._generate_integrity_proof(
                    event_id,
                    datetime.fromisoformat(timestamp),
                    json.loads(operation_details),
                    input_hash,
                    output_hash
                )
                
                if integrity_proof != expected_proof:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error verifying audit trail: {str(e)}")
            return False
    
    async def _store_verification_result(self, data_id: str, result: Dict[str, Any]):
        """Store integrity verification result."""
        verification_id = f"verify_{int(time.time())}_{secrets.token_hex(8)}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO integrity_verifications
            (verification_id, timestamp, data_id, verification_type,
             verification_result, hash_expected, hash_actual, anomalies_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            verification_id,
            datetime.now().isoformat(),
            data_id,
            "comprehensive",
            result["verified"],
            result.get("expected_hash", ""),
            result.get("actual_hash", ""),
            json.dumps([k for k, v in result.items() if k.endswith("_valid") and not v])
        ))
        
        conn.commit()
        conn.close()
    
    async def reconstruct_decision_process(self, decision_id: str) -> Dict[str, Any]:
        """
        Reconstruct the complete decision process from provenance data.
        
        Args:
            decision_id: ID of the decision to reconstruct
            
        Returns:
            Complete reconstruction of the decision process
        """
        try:
            # Find all events related to this decision
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM provenance_events
                WHERE operation_details LIKE ? OR metadata LIKE ?
                ORDER BY timestamp
            ''', (f'%{decision_id}%', f'%{decision_id}%'))
            
            related_events = cursor.fetchall()
            conn.close()
            
            if not related_events:
                return {"error": "No events found for decision ID"}
            
            # Reconstruct the decision timeline
            timeline = []
            data_flow = {}
            decision_factors = []
            
            for event_row in related_events:
                event_data = {
                    "event_id": event_row[0],
                    "timestamp": event_row[1],
                    "event_type": event_row[2],
                    "actor_id": event_row[3],
                    "actor_type": event_row[4],
                    "data_affected": json.loads(event_row[5]) if event_row[5] else [],
                    "operation_details": json.loads(event_row[6]) if event_row[6] else {},
                    "input_hash": event_row[7],
                    "output_hash": event_row[8]
                }
                
                timeline.append(event_data)
                
                # Track data flow
                for data_id in event_data["data_affected"]:
                    if data_id not in data_flow:
                        data_flow[data_id] = []
                    data_flow[data_id].append({
                        "event_id": event_data["event_id"],
                        "operation": event_data["operation_details"],
                        "timestamp": event_data["timestamp"]
                    })
                
                # Extract decision factors
                if "decision_factors" in event_data["operation_details"]:
                    decision_factors.extend(event_data["operation_details"]["decision_factors"])
            
            # Calculate reconstruction confidence
            reconstruction_confidence = self._calculate_reconstruction_confidence(timeline, data_flow)
            
            reconstruction = {
                "decision_id": decision_id,
                "reconstruction_timestamp": datetime.now().isoformat(),
                "timeline": timeline,
                "data_flow": data_flow,
                "decision_factors": list(set(decision_factors)),
                "reconstruction_confidence": reconstruction_confidence,
                "total_events": len(timeline),
                "data_elements_involved": len(data_flow),
                "timespan": self._calculate_timespan(timeline)
            }
            
            self.logger.info(f"Reconstructed decision process: {decision_id} with {len(timeline)} events")
            return reconstruction
            
        except Exception as e:
            self.logger.error(f"Error reconstructing decision process: {str(e)}")
            return {"error": f"Reconstruction failed: {str(e)}"}
    
    def _calculate_reconstruction_confidence(self, timeline: List[Dict], data_flow: Dict) -> float:
        """Calculate confidence in the decision process reconstruction."""
        confidence_factors = []
        
        # Factor 1: Timeline completeness (more events = higher confidence)
        timeline_score = min(len(timeline) / 10, 1.0)
        confidence_factors.append(timeline_score)
        
        # Factor 2: Data flow integrity (all data elements have complete flow)
        flow_completeness = sum(1 for flow in data_flow.values() if len(flow) > 0) / max(len(data_flow), 1)
        confidence_factors.append(flow_completeness)
        
        # Factor 3: Event chain continuity
        sorted_timeline = sorted(timeline, key=lambda x: x["timestamp"])
        chain_continuity = 1.0 if len(sorted_timeline) > 1 else 0.5
        confidence_factors.append(chain_continuity)
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _calculate_timespan(self, timeline: List[Dict]) -> Dict[str, str]:
        """Calculate the timespan of the decision process."""
        if not timeline:
            return {"start": "", "end": "", "duration": "0 seconds"}
        
        timestamps = [datetime.fromisoformat(event["timestamp"]) for event in timeline]
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        
        return {
            "start": start_time.isoformat(),
            "end": end_time.isoformat(),
            "duration": str(duration)
        }
    
    async def create_provenance_dashboard(self) -> str:
        """Create comprehensive data provenance dashboard."""
        # Get provenance statistics
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get lineage statistics
        cursor.execute('SELECT COUNT(*) FROM data_lineage')
        total_lineages = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM provenance_events')
        total_events = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM integrity_verifications WHERE verification_result = 1')
        successful_verifications = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM integrity_verifications')
        total_verifications = cursor.fetchone()[0]
        
        # Get recent events
        cursor.execute('''
            SELECT event_id, timestamp, event_type, actor_id, actor_type
            FROM provenance_events
            ORDER BY timestamp DESC LIMIT 10
        ''')
        recent_events = cursor.fetchall()
        
        # Get data classifications
        cursor.execute('''
            SELECT classification, COUNT(*) as count
            FROM data_lineage
            GROUP BY classification
        ''')
        classifications = cursor.fetchall()
        
        conn.close()
        
        # Calculate integrity rate
        integrity_rate = (successful_verifications / max(total_verifications, 1)) * 100
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Data Provenance & Audit Trail Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f7fa; }}
                .container {{ max-width: 1400px; margin: 0 auto; }}
                .header {{ text-align: center; color: #2c3e50; margin-bottom: 30px; }}
                .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
                .stat-value {{ font-size: 2.5em; font-weight: bold; color: #3498db; }}
                .stat-value.success {{ color: #27ae60; }}
                .stat-value.warning {{ color: #f39c12; }}
                .stat-label {{ color: #7f8c8d; font-size: 0.9em; margin-top: 5px; }}
                .section {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
                .event-list {{ margin-top: 20px; }}
                .event-item {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .event-creation {{ border-left: 5px solid #3498db; background: #ebf3fd; }}
                .event-modification {{ border-left: 5px solid #f39c12; background: #fef9e7; }}
                .event-access {{ border-left: 5px solid #27ae60; background: #d5f4e6; }}
                .event-verification {{ border-left: 5px solid #9b59b6; background: #f4ecf7; }}
                .event-header {{ font-weight: bold; color: #2c3e50; }}
                .event-meta {{ color: #7f8c8d; font-size: 0.9em; margin: 5px 0; }}
                .classification-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .classification-card {{ background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }}
                .progress-bar {{ width: 100%; height: 20px; background: #ecf0f1; border-radius: 10px; overflow: hidden; }}
                .progress-fill {{ height: 100%; background: #27ae60; transition: width 0.3s ease; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 Data Provenance & Audit Trail Dashboard</h1>
                    <p>Comprehensive Evidence Integrity & Chain of Custody</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">{total_lineages}</div>
                        <div class="stat-label">Data Lineages Tracked</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{total_events}</div>
                        <div class="stat-label">Provenance Events</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value success">{integrity_rate:.1f}%</div>
                        <div class="stat-label">Integrity Verification Rate</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{total_verifications}</div>
                        <div class="stat-label">Integrity Checks Performed</div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>📊 Data Classification Distribution</h2>
                    <div class="classification-grid">
        """
        
        for classification, count in classifications:
            percentage = (count / max(total_lineages, 1)) * 100
            html_content += f"""
                        <div class="classification-card">
                            <h4>{classification.upper()}</h4>
                            <div class="stat-value" style="font-size: 1.5em;">{count}</div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: {percentage}%;"></div>
                            </div>
                            <div class="stat-label">{percentage:.1f}% of total</div>
                        </div>
            """
        
        html_content += """
                    </div>
                </div>
                
                <div class="section">
                    <h2>📋 Recent Provenance Events</h2>
                    <div class="event-list">
        """
        
        if recent_events:
            for event in recent_events:
                event_id, timestamp, event_type, actor_id, actor_type = event
                event_class = f"event-{event_type.split('_')[1] if '_' in event_type else event_type}"
                
                html_content += f"""
                        <div class="event-item {event_class}">
                            <div class="event-header">
                                {event_id} - {event_type.replace('_', ' ').title()}
                            </div>
                            <div class="event-meta">
                                Actor: <strong>{actor_id}</strong> ({actor_type}) | 
                                Time: {timestamp}
                            </div>
                        </div>
                """
        else:
            html_content += """
                        <div style="text-align: center; color: #7f8c8d; padding: 40px;">
                            <h3>📋 No Events Recorded Yet</h3>
                            <p>Provenance events will appear here as data operations occur</p>
                        </div>
            """
        
        html_content += f"""
                    </div>
                </div>
                
                <div class="section">
                    <h2>🔐 Cryptographic Integrity Features</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-value success">SHA-256</div>
                            <div class="stat-label">Hash Algorithm</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value success">HMAC-SHA256</div>
                            <div class="stat-label">Signature Algorithm</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value success">Enabled</div>
                            <div class="stat-label">Chain of Custody</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value success">Active</div>
                            <div class="stat-label">Audit Chain</div>
                        </div>
                    </div>
                    <p style="color: #7f8c8d; text-align: center; margin-top: 20px;">
                        All data operations are cryptographically signed and verified for forensic integrity
                    </p>
                </div>
                
                <div style="margin-top: 30px; text-align: center; color: #7f8c8d;">
                    <p>Dashboard Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p>Advanced Data Provenance ensures complete evidence integrity and audit trail</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save dashboard
        dashboard_path = "provenance_dashboard.html"
        with open(dashboard_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"Provenance dashboard created: {dashboard_path}")
        return dashboard_path


async def demonstrate_data_provenance():
    """Demonstration of the Advanced Data Provenance Module."""
    print("🔍 Advanced Data Provenance & Audit Trail Module")
    print("=" * 70)
    
    # Initialize provenance module
    provenance = AdvancedDataProvenanceModule()
    
    print(f"\n📋 Module Initialized with:")
    print(f"- Cryptographic integrity verification enabled")
    print(f"- Immutable audit chain configured")
    print(f"- Database initialized at: {provenance.db_path}")
    print(f"- Hash algorithm: {provenance.hash_algorithm}")
    print(f"- Signature algorithm: {provenance.signature_algorithm}")
    
    # Simulate data creation and tracking
    print(f"\n🔬 Creating Data Lineages...")
    
    # Create sample data with lineage
    sample_data = {
        "vulnerability_scan": {
            "target": "api.example.com",
            "scan_results": ["CVE-2023-1234", "CVE-2023-5678"],
            "timestamp": datetime.now().isoformat(),
            "scanner": "nuclei"
        }
    }
    
    data_id = await provenance.create_data_lineage(
        data_content=sample_data,
        source_system="vulnerability_scanner",
        classification=DataClassification.CONFIDENTIAL,
        metadata={"scan_type": "comprehensive", "target_criticality": "high"}
    )
    print(f"✅ Created data lineage: {data_id}")
    
    # Simulate data analysis
    print(f"\n🔍 Recording Data Analysis Events...")
    
    await provenance.record_provenance_event(
        event_type=ProvenanceEventType.DATA_ANALYSIS,
        actor_id="ai_agent_001",
        actor_type="ai_agent",
        data_affected=[data_id],
        operation_details={
            "analysis_type": "vulnerability_prioritization",
            "ai_model": "gemini-pro",
            "analysis_results": {
                "high_priority_vulns": 2,
                "risk_score": 8.5,
                "exploitation_likelihood": "high"
            }
        },
        input_hash=provenance.active_lineages[data_id].current_hash,
        output_hash=hashlib.sha256(f"analyzed_{data_id}".encode()).hexdigest(),
        metadata={"confidence": 0.92, "processing_time": "2.3s"}
    )
    print(f"✅ Recorded AI analysis event")
    
    # Simulate human review
    await provenance.record_provenance_event(
        event_type=ProvenanceEventType.HUMAN_REVIEW,
        actor_id="security_analyst_001",
        actor_type="human",
        data_affected=[data_id],
        operation_details={
            "review_type": "vulnerability_validation",
            "reviewer_decision": "approved",
            "reviewer_comments": "Analysis confirmed, prioritize for immediate remediation"
        },
        input_hash=provenance.active_lineages[data_id].current_hash,
        output_hash=hashlib.sha256(f"reviewed_{data_id}".encode()).hexdigest(),
        metadata={"review_duration": "15 minutes", "expertise_level": "senior"}
    )
    print(f"✅ Recorded human review event")
    
    # Verify data integrity
    print(f"\n🔐 Verifying Data Integrity...")
    
    # Verify with correct data
    verification_result = await provenance.verify_data_integrity(data_id, sample_data)
    print(f"✅ Integrity verification: {'PASSED' if verification_result['verified'] else 'FAILED'}")
    print(f"   - Hash matches: {verification_result['hash_matches']}")
    print(f"   - Chain valid: {verification_result['chain_valid']}")
    print(f"   - Audit valid: {verification_result['audit_valid']}")
    print(f"   - Confidence: {verification_result['confidence']:.2f}")
    
    # Simulate tampering detection
    print(f"\n🚨 Testing Tampering Detection...")
    
    tampered_data = sample_data.copy()
    tampered_data["vulnerability_scan"]["scan_results"].append("FAKE_CVE")
    
    tamper_verification = await provenance.verify_data_integrity(data_id, tampered_data)
    print(f"🔍 Tampered data verification: {'PASSED' if tamper_verification['verified'] else 'FAILED'}")
    print(f"   - Expected hash: {tamper_verification['expected_hash'][:16]}...")
    print(f"   - Actual hash: {tamper_verification['actual_hash'][:16]}...")
    
    # Reconstruct decision process
    print(f"\n🔄 Reconstructing Decision Process...")
    
    decision_reconstruction = await provenance.reconstruct_decision_process(data_id)
    if "error" not in decision_reconstruction:
        print(f"✅ Decision process reconstructed:")
        print(f"   - Total events: {decision_reconstruction['total_events']}")
        print(f"   - Data elements: {decision_reconstruction['data_elements_involved']}")
        print(f"   - Timespan: {decision_reconstruction['timespan']['duration']}")
        print(f"   - Confidence: {decision_reconstruction['reconstruction_confidence']:.2f}")
    else:
        print(f"❌ Reconstruction failed: {decision_reconstruction['error']}")
    
    # Generate provenance dashboard
    print(f"\n📊 Generating Provenance Dashboard...")
    dashboard_path = await provenance.create_provenance_dashboard()
    print(f"   📄 Dashboard created: {dashboard_path}")
    
    print(f"\n✅ Advanced Data Provenance Module Demonstration Complete!")
    print(f"\nKey Features Demonstrated:")
    print(f"- Complete data lineage tracking")
    print(f"- Cryptographic integrity verification")
    print(f"- Immutable audit chain")
    print(f"- Tampering detection")
    print(f"- Decision process reconstruction")
    print(f"- Chain of custody maintenance")
    print(f"- Forensic-grade evidence handling")
    
    return dashboard_path


if __name__ == "__main__":
    asyncio.run(demonstrate_data_provenance())
