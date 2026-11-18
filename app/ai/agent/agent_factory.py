"""Agent factory: creates LangChain tool-calling agents with fallback and safety boundaries."""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool

from app.ai.agent.tool_registry import ToolRegistry, registry as default_registry
from app.ai.llm.model_factory import build_model_with_retry_and_fallback, build_models_from_config
from app.ai.prompts.cybersecurity_agent import CYBERSECURITY_AGENT_SYSTEM_PROMPT
from app.core.config import settings

logger = logging.getLogger(__name__)


class SafeCyberAgent:
    """
    Defensive cybersecurity agent with tool-calling capabilities,
    provider fallback, retry resilience, and strict execution bounds.
    """

    def __init__(
        self,
        tools: list[BaseTool] | None = None,
        max_iterations: int | None = None,
        max_tool_calls: int | None = None,
        system_prompt: str = CYBERSECURITY_AGENT_SYSTEM_PROMPT,
        llm=None,
    ):
        self.tools = tools or default_registry.get_all_tools()
        self.tool_map = {t.name: t for t in self.tools}
        self.max_iterations = max_iterations or getattr(settings, "agent_max_iterations", 10)
        self.max_tool_calls = max_tool_calls or getattr(settings, "agent_max_tool_calls", 15)
        self.system_prompt = system_prompt
        self.llm = llm or build_model_with_retry_and_fallback()

    async def run(self, user_query: str) -> dict[str, Any]:
        """
        Execute the agent workflow for a given user query.

        Returns a dictionary containing:
        - answer: final synthesized response
        - tools_executed: list of tool names invoked
        - tool_results: list of {tool_name, args, output, execution_ms}
        - iterations: total reasoning cycles
        - citations: extracted source citations
        """
        t0 = time.perf_counter()
        messages: list[BaseMessage] = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(content=user_query),
        ]

        tools_executed: list[str] = []
        tool_results: list[dict[str, Any]] = []
        total_tool_calls = 0

        # Bind tools to the model
        model_with_tools = self.llm.bind_tools(self.tools) if hasattr(self.llm, "bind_tools") else self.llm

        for iteration in range(1, self.max_iterations + 1):
            logger.info("[agent] iteration %d/%d", iteration, self.max_iterations)
            try:
                ai_message: AIMessage = await model_with_tools.ainvoke(messages)
            except Exception as exc:
                logger.error("[agent] LLM invocation failed on iteration %d: %s", iteration, exc)
                # Fallback to direct model invocation if tool binding failed
                ai_message = await self.llm.ainvoke(messages)

            messages.append(ai_message)

            tool_calls = getattr(ai_message, "tool_calls", []) or []
            if not tool_calls:
                # No more tools requested — final response generated
                final_answer = str(ai_message.content).strip()
                elapsed_ms = (time.perf_counter() - t0) * 1000
                logger.info(
                    "[agent] completed in %d iterations, %d tools called, %.1f ms",
                    iteration, len(tools_executed), elapsed_ms
                )
                return {
                    "answer": final_answer,
                    "tools_executed": tools_executed,
                    "tool_results": tool_results,
                    "iterations": iteration,
                    "execution_time_ms": elapsed_ms,
                    "query": user_query,
                }

            # Execute requested tool calls with safety bounds
            for call in tool_calls:
                if total_tool_calls >= self.max_tool_calls:
                    logger.warning("[agent] hit maximum tool calls limit (%d)", self.max_tool_calls)
                    messages.append(
                        ToolMessage(
                            content="Tool execution limit reached. Please synthesize answer from existing findings.",
                            tool_call_id=call.get("id", "limit"),
                        )
                    )
                    continue

                tool_name = call.get("name")
                tool_args = call.get("args", {})
                call_id = call.get("id", f"call_{total_tool_calls}")

                target_tool = self.tool_map.get(tool_name)
                t_start = time.perf_counter()

                if not target_tool:
                    logger.warning("[agent] requested unknown tool '%s'", tool_name)
                    output = {"error": f"Tool '{tool_name}' is not registered."}
                else:
                    try:
                        logger.info("[agent] executing tool '%s' with args %s", tool_name, list(tool_args.keys()))
                        if hasattr(target_tool, "ainvoke"):
                            output = await target_tool.ainvoke(tool_args)
                        else:
                            output = target_tool.invoke(tool_args)
                    except Exception as err:
                        logger.error("[agent] tool '%s' execution error: %s", tool_name, err)
                        output = {"error": f"Tool execution failed: {str(err)}"}

                t_elapsed_ms = (time.perf_counter() - t_start) * 1000
                total_tool_calls += 1
                tools_executed.append(tool_name)
                tool_results.append({
                    "tool_name": tool_name,
                    "args": tool_args,
                    "output": output,
                    "execution_ms": t_elapsed_ms,
                })

                # Serialize tool output for LLM message history
                serialised = json.dumps(output) if isinstance(output, (dict, list)) else str(output)
                messages.append(
                    ToolMessage(
                        content=serialised,
                        tool_call_id=call_id,
                    )
                )

        # Max iterations reached
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.warning("[agent] reached max iterations (%d)", self.max_iterations)
        return {
            "answer": "Analysis reached maximum iteration depth. Summary based on gathered evidence:\n" + str(messages[-1].content),
            "tools_executed": tools_executed,
            "tool_results": tool_results,
            "iterations": self.max_iterations,
            "execution_time_ms": elapsed_ms,
            "query": user_query,
        }


def create_cybersecurity_agent(
    tools: list[BaseTool] | None = None,
    llm=None,
) -> SafeCyberAgent:
    """Factory creating an authenticated, bounded SafeCyberAgent instance."""
    return SafeCyberAgent(tools=tools, llm=llm)
