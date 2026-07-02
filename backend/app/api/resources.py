"""
Demo protected resource endpoints. Each requires a DIFFERENT permission, so you
can log in as different roles and watch RBAC allow/deny per action. This is the
"RBAC applied to every endpoint" demonstration.
"""
from fastapi import APIRouter, Depends

from app.core.deps import CurrentPrincipal, require_permission
from app.schemas.core import MessageResponse

router = APIRouter(prefix="/documents", tags=["demo-resource"])


@router.get("", response_model=MessageResponse, dependencies=[Depends(require_permission("document:read"))])
async def list_documents():
    return MessageResponse(message="Here are the documents (document:read granted)")


@router.post("", response_model=MessageResponse, dependencies=[Depends(require_permission("document:write"))])
async def create_document():
    return MessageResponse(message="Document created (document:write granted)")


@router.post("/{doc_id}/share", response_model=MessageResponse, dependencies=[Depends(require_permission("document:share"))])
async def share_document(doc_id: int):
    return MessageResponse(message=f"Document {doc_id} shared (document:share granted)")


@router.delete("/{doc_id}", response_model=MessageResponse, dependencies=[Depends(require_permission("document:delete"))])
async def delete_document(doc_id: int, principal: CurrentPrincipal):
    return MessageResponse(message=f"Document {doc_id} deleted by user {principal.user_id} (document:delete granted)")
