package tokens

import (
	"testing"
	"time"
)

func TestSessionManagerCreateStoresSessionBySIDAndTID(t *testing.T) {
	t.Parallel()

	services := newRuntimeTestServices(t)
	manager := services.Session()

	tid, token, err := manager.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload, err := manager.Get(token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if payload.SID == "" {
		t.Fatal("expected non-empty sid")
	}
	if payload.TID != tid.String() {
		t.Fatalf("payload tid = %q, want %q", payload.TID, tid.String())
	}

	sidRecord, err := services.Global().GetRawJSON(manager.sidKey(payload.SID))
	if err != nil {
		t.Fatalf("GetRawJSON sid: %v", err)
	}
	if sidRecord == nil {
		t.Fatal("expected session:sid record")
	}

	tidRecord, err := services.Global().GetRawJSON(manager.tidKey(payload.TID))
	if err != nil {
		t.Fatalf("GetRawJSON tid: %v", err)
	}
	if tidRecord == nil {
		t.Fatal("expected session:tid record")
	}
}

func TestSessionManagerRenewKeepsSIDRotatesTIDAndInvalidatesOldToken(t *testing.T) {
	t.Parallel()

	services := newRuntimeTestServices(t)
	manager := services.Session()

	_, token, err := manager.Create()
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload, err := manager.Get(token)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	payload.AddUser("user-1")
	payload.ExpiresAt = time.Now().Add(24 * time.Hour)
	if err := manager.Set(token, payload); err != nil {
		t.Fatalf("Set: %v", err)
	}

	renewedPayload, renewedToken, err := manager.Renew(token)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewedPayload.SID != payload.SID {
		t.Fatalf("renewed sid = %q, want %q", renewedPayload.SID, payload.SID)
	}
	if renewedPayload.TID == payload.TID {
		t.Fatalf("renewed tid = %q, want rotation", renewedPayload.TID)
	}

	if _, err := manager.Get(token); err == nil {
		t.Fatal("expected old token to be invalid after renewal")
	}

	current, err := manager.Get(renewedToken)
	if err != nil {
		t.Fatalf("Get renewed token: %v", err)
	}
	if current.SID != payload.SID {
		t.Fatalf("current sid = %q, want %q", current.SID, payload.SID)
	}
	if !current.HasUser("user-1") {
		t.Fatalf("expected renewed session users to persist, got %#v", current.Users)
	}

	oldRecord, err := services.Global().GetRawJSON(manager.tidKey(payload.TID))
	if err != nil {
		t.Fatalf("GetRawJSON old tid: %v", err)
	}
	if oldRecord != nil {
		t.Fatalf("expected old tid record to be deleted, got %#v", oldRecord)
	}
}
