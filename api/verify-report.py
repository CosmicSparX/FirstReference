import hashlib
import json
import uuid
from datetime import datetime

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

import ipfshttpclient
from web3 import Web3

# Configure Web3 connection
w3 = Web3(Web3.HTTPProvider(settings.ETHEREUM_NODE_URL))
contract_address = settings.CONTRACT_ADDRESS
with open(settings.CONTRACT_ABI_PATH) as f:
    contract_abi = json.load(f)
contract = w3.eth.contract(address=contract_address, abi=contract_abi)

# Configure IPFS connection
ipfs_client = ipfshttpclient.connect(settings.IPFS_API_URL)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_report(request):
    """
    Endpoint to verify a report, store it on IPFS, and record the hash on blockchain
    """
    try:
        # Get report data from request
        report_data = request.data.get('report_data')
        if not report_data:
            return JsonResponse({'error': 'Report data is required'}, status=400)

        # Add metadata to the report
        report_with_metadata = {
            'report_data': report_data,
            'verified_by': request.user.username,
            'verified_at': datetime.now().isoformat(),
            'verification_id': str(uuid.uuid4())
        }

        # Convert to JSON for consistent hashing
        report_json = json.dumps(report_with_metadata, sort_keys=True)

        # Calculate report hash (will be used as the reportId on blockchain)
        report_hash = hashlib.sha256(report_json.encode()).hexdigest()
        report_id = '0x' + report_hash

        # Store report in IPFS
        ipfs_result = ipfs_client.add_json(report_with_metadata)
        ipfs_hash = ipfs_result

        # Prepare to interact with the blockchain
        account = settings.ETHEREUM_ACCOUNT_ADDRESS
        private_key = settings.ETHEREUM_PRIVATE_KEY

        # Build transaction to call verifyReport on the smart contract
        nonce = w3.eth.get_transaction_count(account)
        report_id_bytes32 = w3.to_bytes(hexstr=report_id)

        # Create the transaction
        tx = contract.functions.verifyReport(
            report_id_bytes32,
            ipfs_hash
        ).build_transaction({
            'chainId': settings.ETHEREUM_CHAIN_ID,
            'gas': 2000000,
            'gasPrice': w3.to_wei('50', 'gwei'),
            'nonce': nonce,
        })

        # Sign and send the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        # Wait for the transaction to be mined
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        # Return success response with transaction and IPFS information
        return JsonResponse({
            'status': 'success',
            'message': 'Report verified and stored on blockchain',
            'report_id': report_id,
            'ipfs_hash': ipfs_hash,
            'transaction_hash': tx_hash.hex(),
            'block_number': tx_receipt['blockNumber']
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

# Add this to your urls.py
#