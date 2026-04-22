import { Trash } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from '@/components/ui/select';
import {
    EngagementDocument,
    ScopeDirection,
    type ScopeRuleFragmentFragment,
    ScopeRuleType,
    useAddScopeRuleMutation,
    useDeleteScopeRuleMutation,
} from '@/graphql/types';

const ruleTypeOptions: { label: string; value: ScopeRuleType }[] = [
    { label: 'CIDR', value: ScopeRuleType.Cidr },
    { label: 'IP', value: ScopeRuleType.Ip },
    { label: 'Domain', value: ScopeRuleType.Domain },
    { label: 'Domain glob', value: ScopeRuleType.DomainGlob },
    { label: 'URL prefix', value: ScopeRuleType.UrlPrefix },
    { label: 'Container image', value: ScopeRuleType.ContainerImage },
    { label: 'Container registry', value: ScopeRuleType.ContainerRegistry },
];

const ruleTypeLabel: Record<ScopeRuleType, string> = Object.fromEntries(
    ruleTypeOptions.map((o) => [o.value, o.label]),
) as Record<ScopeRuleType, string>;

interface ScopeRuleEditorProps {
    engagementId: string;
    rules: ScopeRuleFragmentFragment[];
}

export function ScopeRuleEditor({ engagementId, rules }: ScopeRuleEditorProps) {
    const [ruleType, setRuleType] = useState<ScopeRuleType>(ScopeRuleType.Domain);
    const [value, setValue] = useState('');
    const [direction, setDirection] = useState<ScopeDirection>(ScopeDirection.Include);
    const [note, setNote] = useState('');

    const refetch = [{ query: EngagementDocument, variables: { id: engagementId } }];
    const [addRule, { loading: adding }] = useAddScopeRuleMutation({ refetchQueries: refetch });
    const [deleteRule] = useDeleteScopeRuleMutation({ refetchQueries: refetch });

    const handleAdd = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();

        const trimmed = value.trim();

        if (!trimmed) {
            return;
        }

        try {
            await addRule({
                variables: {
                    engagementId,
                    input: {
                        direction,
                        note: note.trim() ? note.trim() : undefined,
                        ruleType,
                        value: trimmed,
                    },
                },
            });

            setValue('');
            setNote('');
            toast.success('Scope rule added');
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Failed to add scope rule';
            toast.error(message);
        }
    };

    const handleDelete = async (id: string) => {
        try {
            await deleteRule({ variables: { id } });
            toast.success('Scope rule removed');
        } catch (err) {
            const message = err instanceof Error ? err.message : 'Failed to delete scope rule';
            toast.error(message);
        }
    };

    return (
        <div className="flex flex-col gap-4">
            <div>
                <h3 className="text-sm font-semibold">Scope rules</h3>
                <p className="text-muted-foreground text-xs">
                    Rules determine which findings are in-scope for this engagement. INCLUDE rules are required; EXCLUDE rules
                    carve out carve-outs.
                </p>
            </div>

            {rules.length === 0 ? (
                <div className="text-muted-foreground rounded-md border border-dashed p-4 text-center text-xs">
                    No scope rules yet — add one below.
                </div>
            ) : (
                <ul className="flex flex-col gap-2">
                    {rules.map((rule) => (
                        <li
                            className="bg-muted/40 flex items-center gap-2 rounded-md border p-2 text-sm"
                            key={rule.id}
                        >
                            <Badge variant={rule.direction === ScopeDirection.Include ? 'secondary' : 'destructive'}>
                                {rule.direction === ScopeDirection.Include ? 'Include' : 'Exclude'}
                            </Badge>
                            <span className="text-muted-foreground font-mono text-xs">
                                {ruleTypeLabel[rule.ruleType] ?? rule.ruleType}
                            </span>
                            <span className="font-mono">{rule.value}</span>
                            {rule.note && (
                                <span className="text-muted-foreground ml-2 truncate text-xs">— {rule.note}</span>
                            )}
                            <Button
                                aria-label="Delete scope rule"
                                className="ml-auto"
                                onClick={() => handleDelete(rule.id)}
                                size="icon-sm"
                                type="button"
                                variant="ghost"
                            >
                                <Trash />
                            </Button>
                        </li>
                    ))}
                </ul>
            )}

            <form
                className="flex flex-wrap items-end gap-2"
                onSubmit={handleAdd}
            >
                <div className="flex flex-col gap-1">
                    <label
                        className="text-muted-foreground text-xs"
                        htmlFor="scope-direction"
                    >
                        Direction
                    </label>
                    <Select
                        onValueChange={(next) => setDirection(next as ScopeDirection)}
                        value={direction}
                    >
                        <SelectTrigger
                            className="w-32"
                            id="scope-direction"
                        >
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            <SelectItem value={ScopeDirection.Include}>Include</SelectItem>
                            <SelectItem value={ScopeDirection.Exclude}>Exclude</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
                <div className="flex flex-col gap-1">
                    <label
                        className="text-muted-foreground text-xs"
                        htmlFor="scope-rule-type"
                    >
                        Type
                    </label>
                    <Select
                        onValueChange={(next) => setRuleType(next as ScopeRuleType)}
                        value={ruleType}
                    >
                        <SelectTrigger
                            className="w-44"
                            id="scope-rule-type"
                        >
                            <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                            {ruleTypeOptions.map((option) => (
                                <SelectItem
                                    key={option.value}
                                    value={option.value}
                                >
                                    {option.label}
                                </SelectItem>
                            ))}
                        </SelectContent>
                    </Select>
                </div>
                <div className="flex flex-1 flex-col gap-1">
                    <label
                        className="text-muted-foreground text-xs"
                        htmlFor="scope-value"
                    >
                        Value
                    </label>
                    <Input
                        id="scope-value"
                        onChange={(e) => setValue(e.target.value)}
                        placeholder="e.g. *.example.com or 10.0.0.0/8"
                        value={value}
                    />
                </div>
                <div className="flex flex-1 flex-col gap-1">
                    <label
                        className="text-muted-foreground text-xs"
                        htmlFor="scope-note"
                    >
                        Note (optional)
                    </label>
                    <Input
                        id="scope-note"
                        onChange={(e) => setNote(e.target.value)}
                        placeholder="e.g. production only"
                        value={note}
                    />
                </div>
                <Button
                    disabled={adding || !value.trim()}
                    type="submit"
                >
                    {adding ? 'Adding...' : 'Add rule'}
                </Button>
            </form>
        </div>
    );
}
