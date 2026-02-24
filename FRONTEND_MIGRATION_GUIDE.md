# Frontend Migration Guide — `user_agent` → `agents` 테이블 전환

`user_agent` 테이블이 삭제되고, 기존 JSONB 데이터가 `agents` 테이블의 개별 컬럼으로 풀어졌습니다.  
아래 3개 엔드포인트의 request/response가 변경되었으므로 프론트엔드 fetch 코드를 수정해야 합니다.

---

## 1. `POST /users/agents/list` — 에이전트 목록 조회

### Request (변경 없음)

```json
{
  "access_token": "<JWT>"
}
```

### Response (변경됨)

각 에이전트가 JSONB 파싱 결과가 아니라 **개별 컬럼**으로 내려옵니다.

```json
{
  "status": "success",
  "agents": [
    {
      "slug": "my-agent",
      "base_slug": "base",
      "name": "My Agent",
      "description": "설명",
      "version": "1.0",
      "price": 0,
      "icon": "🤖",
      "category": "기타",
      "config": { ... },
      "model_card": "...",
      "docker_image": false,
      "created_at": 1700000000000,
      "updated_at": 1700000000000,
      "user_id": "user123"
    }
  ]
}
```

**프론트엔드 주의사항:**
- `created_at`, `updated_at`이 Unix epoch **밀리초**(정수)로 내려옵니다.
- `config`는 JSONB 객체(Object)로 그대로 내려옵니다.
- `model_card`, `embedding`은 `null`일 수 있습니다.
- 기존에 JSONB 내부에 존재하지 않던 필드(`created_at`, `updated_at`, `user_id`)가 추가되었으니, 필요에 따라 UI에 반영하세요.

---

## 2. `POST /users/agents` — 에이전트 추가

### Request (변경됨)

`agent` 객체에 **반드시 `slug` 필드가 포함**되어야 합니다.

```js
// Before (❌ 더 이상 동작하지 않음)
fetch("/users/agents", {
  method: "POST",
  body: JSON.stringify({
    access_token: token,
    agent: { /* 전체 JSON blob */ }
  })
});

// After (✅)
fetch("/users/agents", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    access_token: token,
    agent: {
      slug: "my-agent",           // 필수
      base_slug: "base",          // 선택 (기본값: "")
      name: "My Agent",           // 선택 (기본값: "")
      description: "설명",        // 선택 (기본값: "")
      version: "1.0",             // 선택 (기본값: "")
      price: 0,                   // 선택 (기본값: 0)
      icon: "🤖",                 // 선택 (기본값: "🤖")
      category: "기타",           // 선택 (기본값: "기타")
      config: { /* ... */ },      // 선택 (기본값: null)
      model_card: "...",          // 선택 (기본값: null)
      docker_image: false         // 선택 (기본값: false)
    }
  })
});
```

### Response (변경됨)

```json
// Before
{ "status": "success", "inserted": true, "agent_id": 42 }

// After
{ "status": "success", "inserted": true, "slug": "my-agent" }
```

| 항목 | Before | After |
|------|--------|-------|
| 식별자 키 | `agent_id` (숫자) | `slug` (문자열) |
| 충돌 기준 | `(user_id, agent)` JSONB 전체 | `slug` (Primary Key) |

---

## 3. `DELETE /users/agents` — 에이전트 삭제

### Request (변경됨 ⚠️)

기존에는 `agent` 전체 JSON을 보내야 했지만, 이제 **`slug` 문자열만** 보내면 됩니다.

```js
// Before (❌ 더 이상 동작하지 않음)
fetch("/users/agents", {
  method: "DELETE",
  body: JSON.stringify({
    access_token: token,
    agent: { slug: "my-agent", name: "...", /* 전체 객체 */ }
  })
});

// After (✅)
fetch("/users/agents", {
  method: "DELETE",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    access_token: token,
    slug: "my-agent"      // slug만 전달
  })
});
```

### Response (변경 없음)

```json
{ "status": "success", "deleted": true, "deleted_count": 1 }
```

---

## 변경되지 않은 엔드포인트

아래 엔드포인트들은 이번 마이그레이션의 영향을 받지 않습니다.

| 엔드포인트 | 메서드 |
|------------|--------|
| `/signup` | POST |
| `/signin` | POST |
| `/users/subscriptions/list` | POST |
| `/users/subscriptions` | POST / DELETE |
| `/users/chat/history` | POST |
| `/users/chat/save` | POST |
| `/healthcheck` | GET |

---

## 체크리스트

- [ ] `POST /users/agents` 호출 시 `agent.slug` 필수 포함 확인
- [ ] `POST /users/agents` 응답에서 `agent_id` → `slug`로 변수명 변경
- [ ] `DELETE /users/agents` 호출 시 `agent` 객체 대신 `slug` 문자열 전달
- [ ] `POST /users/agents/list` 응답의 agent 구조 변경 대응 (개별 컬럼 기반)
- [ ] `created_at`, `updated_at` 타임스탬프(밀리초) 처리 확인
