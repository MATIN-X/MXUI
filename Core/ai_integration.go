// MXUI VPN Panel
// Core/ai_integration.go
// AI Integration for Smart Routing & Optimization

package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// ============================================================================
// AI CONSTANTS
// ============================================================================

const (
	ChatGPTEndpoint = "https://api.openai.com/v1/chat/completions"
	GeminiEndpoint  = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"

	AITimeout      = 30 * time.Second
	AICacheTimeout = 1 * time.Hour
	AIMaxRetries   = 3
)

// AI Provider types
const (
	ProviderChatGPT = "chatgpt"
	ProviderGemini  = "gemini"
)

// ============================================================================
// AI MANAGER
// ============================================================================

// AIManager manages AI integration
type AIManager struct {
	enabled    bool
	provider   string
	apiKey     string
	model      string
	cache      map[string]*AIResponse
	cacheMu    sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	httpClient *http.Client
}

// AIRequest represents an AI request
type AIRequest struct {
	Prompt      string
	Context     map[string]interface{}
	MaxTokens   int
	Temperature float64
}

// AIResponse represents an AI response
type AIResponse struct {
	Response   string
	Timestamp  time.Time
	Provider   string
	Model      string
	TokensUsed int
}

// RoutingAdvice represents AI routing advice
type RoutingAdvice struct {
	RecommendedProtocol string
	RecommendedOutbound string
	Reason              string
	AlternativeOptions  []string
	Confidence          float64
}

// TrafficAnalysis represents AI traffic analysis
type TrafficAnalysis struct {
	IsAbnormal        bool
	ThreatLevel       string // low, medium, high
	Description       string
	RecommendedAction string
	Patterns          []string
}

// AIConfig represents AI configuration
type AIConfig struct {
	Enabled  bool   `yaml:"enabled" json:"enabled"`
	Provider string `yaml:"provider" json:"provider"` // chatgpt, gemini
	APIKey   string `yaml:"api_key" json:"api_key"`
	Model    string `yaml:"model" json:"model"`
}

// Global AI manager
var AI *AIManager

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitAIManager initializes AI integration
func InitAIManager(enabled bool, provider, apiKey, model string) error {
	ctx, cancel := context.WithCancel(context.Background())

	AI = &AIManager{
		enabled:  enabled,
		provider: provider,
		apiKey:   apiKey,
		model:    model,
		cache:    make(map[string]*AIResponse),
		ctx:      ctx,
		cancel:   cancel,
		httpClient: &http.Client{
			Timeout: AITimeout,
		},
	}

	if !enabled {
		LogInfo("AI", "AI integration disabled")
		return nil
	}

	if apiKey == "" {
		return fmt.Errorf("AI API key required")
	}

	// Start cache cleanup
	go AI.cleanupCache()

	LogSuccess("AI", "AI integration initialized with %s (%s)", provider, model)
	return nil
}

// ============================================================================
// SMART ROUTING
// ============================================================================

// GetRoutingAdvice gets AI-powered routing advice
func (ai *AIManager) GetRoutingAdvice(userID int64, targetSite string) (*RoutingAdvice, error) {
	if !ai.enabled {
		return nil, fmt.Errorf("AI not enabled")
	}

	// Build context
	context := map[string]interface{}{
		"user_id":     userID,
		"target_site": targetSite,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	// Get user stats
	if user, err := Users.GetUserByID(userID); err == nil {
		context["user_traffic"] = user.DownloadUsed + user.UploadUsed
		context["user_protocols"] = ai.getUserProtocols(userID)
	}

	// Get current network status
	context["node_status"] = ai.getNodeStatus()

	// Build prompt
	prompt := fmt.Sprintf(`
You are a VPN routing expert. Analyze the following context and recommend the best protocol and outbound for this user.

Context:
- Target site: %s
- User traffic: %.2f GB
- Available protocols: VMess, VLESS, Trojan, Shadowsocks, Hysteria2, TUIC
- Available outbounds: Direct, WARP, Freedom, Blackhole

Provide your recommendation in JSON format:
{
  "protocol": "...",
  "outbound": "...",
  "reason": "...",
  "alternatives": ["...", "..."],
  "confidence": 0.95
}
`, targetSite, float64(context["user_traffic"].(int64))/1024/1024/1024)

	// Get AI response
	response, err := ai.Query(&AIRequest{
		Prompt:      prompt,
		Context:     context,
		MaxTokens:   500,
		Temperature: 0.3,
	})

	if err != nil {
		return nil, err
	}

	// Parse response
	var advice RoutingAdvice
	if err := json.Unmarshal([]byte(response.Response), &advice); err != nil {
		// Fallback parsing
		advice = RoutingAdvice{
			RecommendedProtocol: "VLESS",
			RecommendedOutbound: "WARP",
			Reason:              response.Response,
			Confidence:          0.5,
		}
	}

	LogInfo("AI", "Routing advice for %s: %s + %s (%.0f%% confidence)",
		targetSite, advice.RecommendedProtocol, advice.RecommendedOutbound, advice.Confidence*100)

	return &advice, nil
}

// AnalyzeTraffic analyzes traffic patterns for abnormalities
func (ai *AIManager) AnalyzeTraffic(userID int64, traffic map[string]interface{}) (*TrafficAnalysis, error) {
	if !ai.enabled {
		return nil, fmt.Errorf("AI not enabled")
	}

	prompt := fmt.Sprintf(`
Analyze the following VPN traffic pattern for abnormalities or potential threats:

Traffic Data:
%s

Determine if this traffic is abnormal and provide analysis in JSON format:
{
  "is_abnormal": true/false,
  "threat_level": "low|medium|high",
  "description": "...",
  "recommended_action": "...",
  "patterns": ["...", "..."]
}
`, formatJSON(traffic))

	response, err := ai.Query(&AIRequest{
		Prompt:      prompt,
		MaxTokens:   500,
		Temperature: 0.2,
	})

	if err != nil {
		return nil, err
	}

	var analysis TrafficAnalysis
	if err := json.Unmarshal([]byte(response.Response), &analysis); err != nil {
		analysis = TrafficAnalysis{
			IsAbnormal:  false,
			ThreatLevel: "low",
			Description: response.Response,
		}
	}

	if analysis.IsAbnormal {
		LogWarn("AI", "Abnormal traffic detected for user %d: %s", userID, analysis.Description)
	}

	return &analysis, nil
}

// OptimizeUserConfig optimizes user configuration
func (ai *AIManager) OptimizeUserConfig(userID int64) (map[string]interface{}, error) {
	if !ai.enabled {
		return nil, fmt.Errorf("AI not enabled")
	}

	user, err := Users.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	usedTraffic := float64(user.DownloadUsed+user.UploadUsed) / (1024 * 1024 * 1024)
	totalTraffic := float64(user.DataLimit) / (1024 * 1024 * 1024)

	prompt := fmt.Sprintf(`
Optimize VPN configuration for this user based on their usage pattern:

User Stats:
- Traffic used: %.2f GB / %.2f GB
- Connection count: %d
- Average speed: %.2f Mbps
- Most used protocol: %s

Recommend optimized settings in JSON format:
{
  "protocol": "...",
  "encryption": "...",
  "mux": true/false,
  "tcp_settings": {...},
  "udp_settings": {...}
}
`, usedTraffic, totalTraffic, 0, 0.0, "VLESS")

	response, err := ai.Query(&AIRequest{
		Prompt:      prompt,
		MaxTokens:   800,
		Temperature: 0.4,
	})

	if err != nil {
		return nil, err
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(response.Response), &config); err != nil {
		return nil, err
	}

	LogInfo("AI", "Optimized config generated for user %d", userID)
	return config, nil
}

// ============================================================================
// CHATBOT ASSISTANT
// ============================================================================

// ChatAssistant provides AI chatbot responses
func (ai *AIManager) ChatAssistant(userMessage string, context map[string]interface{}) (string, error) {
	if !ai.enabled {
		return "AI assistant is not available.", nil
	}

	systemPrompt := `You are a helpful VPN panel assistant. Answer user questions about:
- VPN configuration and setup
- Protocol selection (VMess, VLESS, Trojan, etc.)
- Troubleshooting connection issues
- Traffic management
- Security best practices

Be concise and helpful. Use simple language.`

	prompt := fmt.Sprintf("%s\n\nUser: %s\n\nAssistant:", systemPrompt, userMessage)

	response, err := ai.Query(&AIRequest{
		Prompt:      prompt,
		Context:     context,
		MaxTokens:   500,
		Temperature: 0.7,
	})

	if err != nil {
		return "Sorry, I encountered an error. Please try again.", err
	}

	return response.Response, nil
}

// ============================================================================
// AI QUERY
// ============================================================================

// Query sends a query to the AI provider
func (ai *AIManager) Query(req *AIRequest) (*AIResponse, error) {
	// Check cache
	cacheKey := ai.getCacheKey(req.Prompt)
	if cached := ai.getCache(cacheKey); cached != nil {
		LogDebug("AI", "Cache hit for query")
		return cached, nil
	}

	var response *AIResponse
	var err error

	switch ai.provider {
	case ProviderChatGPT:
		response, err = ai.queryChatGPT(req)
	case ProviderGemini:
		response, err = ai.queryGemini(req)
	default:
		return nil, fmt.Errorf("unknown AI provider: %s", ai.provider)
	}

	if err != nil {
		return nil, err
	}

	// Cache response
	ai.setCache(cacheKey, response)

	return response, nil
}

// queryChatGPT queries OpenAI ChatGPT
func (ai *AIManager) queryChatGPT(req *AIRequest) (*AIResponse, error) {
	payload := map[string]interface{}{
		"model": ai.model,
		"messages": []map[string]string{
			{"role": "user", "content": req.Prompt},
		},
		"max_tokens":  req.MaxTokens,
		"temperature": req.Temperature,
	}

	if req.MaxTokens == 0 {
		payload["max_tokens"] = 1000
	}
	if req.Temperature == 0 {
		payload["temperature"] = 0.7
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", ChatGPTEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+ai.apiKey)

	resp, err := ai.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ChatGPT API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return nil, fmt.Errorf("no response from ChatGPT")
	}

	return &AIResponse{
		Response:   result.Choices[0].Message.Content,
		Timestamp:  time.Now(),
		Provider:   ProviderChatGPT,
		Model:      ai.model,
		TokensUsed: result.Usage.TotalTokens,
	}, nil
}

// queryGemini queries Google Gemini
func (ai *AIManager) queryGemini(req *AIRequest) (*AIResponse, error) {
	payload := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": req.Prompt},
				},
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := GeminiEndpoint + "?key=" + ai.apiKey

	httpReq, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := ai.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Gemini API error: %s - %s", resp.Status, string(body))
	}

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no response from Gemini")
	}

	return &AIResponse{
		Response:  result.Candidates[0].Content.Parts[0].Text,
		Timestamp: time.Now(),
		Provider:  ProviderGemini,
		Model:     ai.model,
	}, nil
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

func (ai *AIManager) getCacheKey(prompt string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(prompt)))
}

func (ai *AIManager) getCache(key string) *AIResponse {
	ai.cacheMu.RLock()
	defer ai.cacheMu.RUnlock()

	cached, exists := ai.cache[key]
	if !exists {
		return nil
	}

	if time.Since(cached.Timestamp) > AICacheTimeout {
		return nil
	}

	return cached
}

func (ai *AIManager) setCache(key string, response *AIResponse) {
	ai.cacheMu.Lock()
	defer ai.cacheMu.Unlock()

	ai.cache[key] = response
}

func (ai *AIManager) cleanupCache() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ai.ctx.Done():
			return
		case <-ticker.C:
			ai.cacheMu.Lock()
			for key, response := range ai.cache {
				if time.Since(response.Timestamp) > AICacheTimeout {
					delete(ai.cache, key)
				}
			}
			ai.cacheMu.Unlock()
		}
	}
}

// ============================================================================
// HELPERS
// ============================================================================

func (ai *AIManager) getUserProtocols(userID int64) []string {
	// TODO: Get user's inbound protocols
	return []string{"VLESS", "VMess", "Trojan"}
}

func (ai *AIManager) getNodeStatus() map[string]interface{} {
	if MasterNode == nil {
		return nil
	}

	status := make(map[string]interface{})
	nodes := MasterNode.GetNodeStatus()

	status["total"] = len(nodes)
	status["online"] = 0

	for _, node := range nodes {
		if node.Status == NodeStatusOnline {
			status["online"] = status["online"].(int) + 1
		}
	}

	return status
}

func formatJSON(data interface{}) string {
	bytes, _ := json.MarshalIndent(data, "", "  ")
	return string(bytes)
}
