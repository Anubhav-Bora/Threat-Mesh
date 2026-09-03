import { useQuery } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { apiModeStore, threatApi } from "../api/client";

const options = {
  staleTime: 60_000,
  retry: false,
  refetchOnWindowFocus: false,
} as const;

export const useApiMode = () =>
  useSyncExternalStore(
    apiModeStore.subscribe,
    apiModeStore.getSnapshot,
    apiModeStore.getSnapshot,
  );
export const useIndicators = (
  provenance: "all" | "live" | "demo" = "all",
  enabled = true,
) =>
  useQuery({
    queryKey: ["indicators", provenance],
    queryFn: () => threatApi.indicators(provenance),
    enabled,
    ...options,
  });
export const useIndicator = (id?: string) =>
  useQuery({
    queryKey: ["indicator", id],
    queryFn: () => threatApi.indicator(id!),
    enabled: Boolean(id),
    ...options,
  });
export const useIndicatorLineage = (id?: string) =>
  useQuery({
    queryKey: ["indicator-lineage", id],
    queryFn: () => threatApi.indicatorLineage(id!),
    enabled: Boolean(id),
    staleTime: 5 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
  });
export const useCampaigns = () =>
  useQuery({
    queryKey: ["campaigns"],
    queryFn: threatApi.campaigns,
    ...options,
  });
export const useCampaign = (id?: string | null) =>
  useQuery({
    queryKey: ["campaign", id],
    queryFn: () => threatApi.campaign(id!),
    enabled: Boolean(id),
    ...options,
  });
export const useTechniques = () =>
  useQuery({
    queryKey: ["techniques"],
    queryFn: threatApi.techniques,
    ...options,
  });
export const useReports = () =>
  useQuery({ queryKey: ["reports"], queryFn: threatApi.reports, ...options });
export const useReport = (id?: string) =>
  useQuery({
    queryKey: ["report", id],
    queryFn: () => threatApi.report(id!),
    enabled: Boolean(id),
    ...options,
  });
export const useReportSchedule = () =>
  useQuery({
    queryKey: ["report-schedule"],
    queryFn: threatApi.reportSchedule,
    ...options,
  });
export const useRules = () =>
  useQuery({ queryKey: ["rules"], queryFn: threatApi.rules, ...options });
export const useSummary = () =>
  useQuery({ queryKey: ["summary"], queryFn: threatApi.summary, ...options });

export const useFeedStatus = () =>
  useQuery({
    queryKey: ["feed-status"],
    queryFn: threatApi.feedStatus,
    refetchInterval: 30_000,
    ...options,
  });
