/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package cavainstrumentationexplorer;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.ComponentListener;
import java.awt.event.FocusListener;
import java.awt.event.HierarchyBoundsListener;
import java.awt.event.HierarchyListener;
import java.awt.event.InputEvent;
import java.awt.event.InputMethodListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseListener;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelListener;
import java.beans.PropertyChangeListener;
import java.util.EventListener;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.DefaultFocusOwnerProvider;
import docking.DialogComponentProvider;
import docking.FocusOwnerProvider;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import docking.actions.PopupActionProvider;
import docking.widgets.PopupKeyStorePasswordProvider;
import docking.widgets.fieldpanel.support.HoverProvider;
import docking.widgets.table.DisplayStringProvider;
import docking.widgets.table.constraint.ColumnConstraintProvider;
import docking.widgets.table.constraint.provider.BooleanMatchColumnConstraintProvider;
import docking.widgets.table.constraint.provider.DateColumnConstraintProvider;
import docking.widgets.table.constraint.provider.IntegerEditorProvider;
import docking.widgets.table.constraint.provider.IntegerRangeEditorProvider;
import docking.widgets.table.constraint.provider.LongEditorProvider;
import docking.widgets.table.constraint.provider.LongRangeEditorProvider;
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;
import docking.widgets.table.constraint.provider.StringColumnConstraintProvider;
import docking.widgets.table.constrainteditor.UnsignedLongConstraintEditorProvider;
import docking.widgets.table.constrainteditor.UnsignedLongRangeEditorProvider;
import docking.widgets.tree.DefaultGTreeFilterProvider;
import docking.widgets.tree.GTreeFilterProvider;
import functioncalls.graph.layout.BowTieLayoutProvider;
import functioncalls.graph.renderer.FcgTooltipProvider;
import functioncalls.plugin.FcgProvider;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.decompiler.component.DecompilerHoverProvider;
import ghidra.app.merge.tool.ListingMergePanelProvider;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.bookmark.BookmarkProvider;
import ghidra.app.plugin.core.byteviewer.ByteViewerClipboardProvider;
import ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider;
import ghidra.app.plugin.core.byteviewer.ByteViewerHighlightProvider;
import ghidra.app.plugin.core.byteviewer.ProgramByteViewerComponentProvider;
import ghidra.app.plugin.core.calltree.CallTreeProvider;
import ghidra.app.plugin.core.checksums.ComputeChecksumsProvider;
import ghidra.app.plugin.core.clipboard.CodeBrowserClipboardProvider;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.codebrowser.ListingHighlightProvider;
import ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider;
import ghidra.app.plugin.core.compositeeditor.EditorProvider;
import ghidra.app.plugin.core.compositeeditor.StructureEditorProvider;
import ghidra.app.plugin.core.compositeeditor.UnionEditorProvider;
import ghidra.app.plugin.core.console.ConsoleComponentProvider;
import ghidra.app.plugin.core.datamgr.DataTypesProvider;
import ghidra.app.plugin.core.datamgr.editor.EnumEditorProvider;
import ghidra.app.plugin.core.decompile.DecompilerClipboardProvider;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider;
import ghidra.app.plugin.core.diff.DiffApplySettingsProvider;
import ghidra.app.plugin.core.diff.DiffDetailsProvider;
import ghidra.app.plugin.core.diff.DiffServiceProvider;
import ghidra.app.plugin.core.editor.TextEditorComponentProvider;
import ghidra.app.plugin.core.equate.EquateTableProvider;
import ghidra.app.plugin.core.functioncompare.FunctionComparisonProvider;
import ghidra.app.plugin.core.functiongraph.FGClipboardProvider;
import ghidra.app.plugin.core.functiongraph.FGColorProvider;
import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.FGSatelliteUndockedProvider;
import ghidra.app.plugin.core.functiongraph.SetFormatDialogComponentProvider;
import ghidra.app.plugin.core.functiongraph.graph.layout.DecompilerNestedLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.layout.ExperimentalLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertexTooltipProvider;
import ghidra.app.plugin.core.functionwindow.FunctionWindowProvider;
import ghidra.app.plugin.core.hover.AbstractHoverProvider;
import ghidra.app.plugin.core.interpreter.InterpreterComponentProvider;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProvider;
import ghidra.app.plugin.core.programtree.ViewManagerComponentProvider;
import ghidra.app.plugin.core.reachability.FunctionReachabilityProvider;
import ghidra.app.plugin.core.references.EditReferencesProvider;
import ghidra.app.plugin.core.references.ExternalReferencesProvider;
import ghidra.app.plugin.core.register.RegisterManagerProvider;
import ghidra.app.plugin.core.scalartable.ScalarSearchProvider;
import ghidra.app.plugin.core.script.GhidraScriptComponentProvider;
import ghidra.app.plugin.core.script.GhidraScriptEditorComponentProvider;
import ghidra.app.plugin.core.stackeditor.StackEditorProvider;
import ghidra.app.plugin.core.string.StringTableProvider;
import ghidra.app.plugin.core.strings.ViewStringsColumnConstraintProvider;
import ghidra.app.plugin.core.strings.ViewStringsProvider;
import ghidra.app.plugin.core.symboltree.SymbolTreeProvider;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.JavaScriptProvider;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.ProgramDropProvider;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.InputStreamByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.MemoryMutableByteProvider;
import ghidra.app.util.bin.MutableByteProvider;
import ghidra.app.util.bin.RandomAccessMutableByteProvider;
import ghidra.app.util.bin.SynchronizedByteProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.BaseSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.CompressedSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DSymSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.DWARFSectionProvider;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.NullSectionProvider;
import ghidra.app.util.viewer.listingpanel.ListingComparisonProvider;
import ghidra.app.util.viewer.listingpanel.ListingDiffHighlightProvider;
import ghidra.app.util.viewer.listingpanel.ListingHoverProvider;
import ghidra.app.util.viewer.listingpanel.MarginProvider;
import ghidra.app.util.viewer.listingpanel.OverviewProvider;
import ghidra.base.widgets.table.constraint.provider.ProgramColumnConstraintProvider;
import ghidra.bitpatterns.gui.BitsInputDialogComponentProvider;
import ghidra.bitpatterns.gui.ByteSequenceAnalyzerProvider;
import ghidra.bitpatterns.gui.FunctionBitPatternsMainProvider;
import ghidra.bitpatterns.gui.InputDialogComponentProvider;
import ghidra.bitpatterns.gui.PatternEvalTableProvider;
import ghidra.bitpatterns.gui.PatternMiningAnalyzerProvider;
import ghidra.bitpatterns.gui.SimpleByteSequenceAnalyzerProvider;
import ghidra.feature.vt.gui.duallisting.VTDualListingHighlightProvider;
import ghidra.feature.vt.gui.filters.AncillaryFilterDialogComponentProvider;
import ghidra.feature.vt.gui.provider.functionassociation.VTFunctionAssociationProvider;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchesTableProvider;
import ghidra.feature.vt.gui.provider.markuptable.MarkupItemFilterDialogComponentProvider;
import ghidra.feature.vt.gui.provider.markuptable.VTMarkupItemsTableProvider;
import ghidra.feature.vt.gui.provider.matchtable.MatchesFilterDialogComponentProvider;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchDestinationTableProvider;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchOneToManyTableProvider;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchSourceTableProvider;
import ghidra.feature.vt.gui.provider.relatedMatches.VTRelatedMatchesTableProvider;
import ghidra.formats.gfilesystem.GFileSystemProgramProvider;
import ghidra.formats.gfilesystem.GIconProvider;
import ghidra.framework.main.datatree.ArchiveProvider;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.dialog.ExtensionTableProvider;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;
import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.JungLayoutProvider;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import ghidra.pcodeCPort.sleighbase.NamedSymbolProvider;
import ghidra.pcodeCPort.translate.BasicSpaceProvider;
import ghidra.program.model.lang.LanguageProvider;
import ghidra.python.PythonScriptProvider;
import ghidra.security.KeyStorePasswordProvider;
import ghidra.util.HelpLocation;
import help.TOCItemProvider;
import help.screenshot.ImageDialogProvider;
import resources.IconProvider;
import resources.Icons;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class CavaInstrumentationExplorerPlugin extends ProgramPlugin {

	String PROVIDER_NAME = "Decomopiler";
	MyProvider provider;
	DockingAction dumpComponentHierarchy;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public CavaInstrumentationExplorerPlugin(PluginTool tool) {
		super(tool);

		// TODO: Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// TODO: Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
		// TODO: Acquire services if necessary
		
	}
	
	public static void exploreComponentHierarchy(PluginTool aTool, String providerName) {
		ComponentProvider aProvider = aTool.getComponentProvider(providerName);
		
		//If the tool cannot lookup the provider, try to use the name as a class name
		if(aProvider == null) { 
			System.out.println("No provider returned by name for ["+providerName+"]. Trying as a class name");
			@SuppressWarnings("rawtypes")
            Class clazz = null;
			
			switch(providerName) {
				//Doing this via a call seemed fraught with perils... e.g. Class.forName(providerName);
			case "AbstractHoverProvider.class": clazz = AbstractHoverProvider.class; break;
			case "AbstractLayoutProvider.class": clazz = AbstractLayoutProvider.class; break;
			case "ActionContextProvider.class": clazz = ActionContextProvider.class; break;
			case "AncillaryFilterDialogComponentProvider.class": clazz = AncillaryFilterDialogComponentProvider.class; break;
			case "ArchiveProvider.class": clazz = ArchiveProvider.class; break;
			case "BaseSectionProvider.class": clazz = BaseSectionProvider.class; break;
			case "BasicSpaceProvider.class": clazz = BasicSpaceProvider.class; break;
			case "BitsInputDialogComponentProvider.class": clazz = BitsInputDialogComponentProvider.class; break;
			case "BookmarkProvider.class": clazz = BookmarkProvider.class; break;
			case "BooleanMatchColumnConstraintProvider.class": clazz = BooleanMatchColumnConstraintProvider.class; break;
			case "BowTieLayoutProvider.class": clazz = BowTieLayoutProvider.class; break;
			//case "BundleStatusComponentProvider.class": clazz = BundleStatusComponentProvider.class; break;
			case "ByteArrayProvider.class": clazz = ByteArrayProvider.class; break;
			case "ByteProvider.class": clazz = ByteProvider.class; break;
			case "ByteSequenceAnalyzerProvider.class": clazz = ByteSequenceAnalyzerProvider.class; break;
			case "ByteViewerClipboardProvider.class": clazz = ByteViewerClipboardProvider.class; break;
			case "ByteViewerComponentProvider.class": clazz = ByteViewerComponentProvider.class; break;
			case "ByteViewerHighlightProvider.class": clazz = ByteViewerHighlightProvider.class; break;
			case "CallTreeProvider.class": clazz = CallTreeProvider.class; break;
			case "CodeBrowserClipboardProvider.class": clazz = CodeBrowserClipboardProvider.class; break;
			case "CodeViewerProvider.class": clazz = CodeViewerProvider.class; break;
			//case "ColorizingServiceProvider.class": clazz = ColorizingServiceProvider.class; break;
			case "ColumnConstraintProvider.class": clazz = ColumnConstraintProvider.class; break;
			//case "CommentWindowProvider.class": clazz = CommentWindowProvider.class; break;
			case "ComponentProvider.class": clazz = ComponentProvider.class; break;
			case "CompositeEditorProvider.class": clazz = CompositeEditorProvider.class; break;
			case "CompressedSectionProvider.class": clazz = CompressedSectionProvider.class; break;
			case "ComputeChecksumsProvider.class": clazz = ComputeChecksumsProvider.class; break;
			case "ConsoleComponentProvider.class": clazz = ConsoleComponentProvider.class; break;
			case "DSymSectionProvider.class": clazz = DSymSectionProvider.class; break;
			case "DWARFSectionProvider.class": clazz = DWARFSectionProvider.class; break;
			case "DataTypesProvider.class": clazz = DataTypesProvider.class; break;
			//case "DataWindowProvider.class": clazz = DataWindowProvider.class; break;
			case "DateColumnConstraintProvider.class": clazz = DateColumnConstraintProvider.class; break;
			case "DecompilerClipboardProvider.class": clazz = DecompilerClipboardProvider.class; break;
			case "DecompilerHoverProvider.class": clazz = DecompilerHoverProvider.class; break;
			case "DecompilerNestedLayoutProvider.class": clazz = DecompilerNestedLayoutProvider.class; break;
			case "DecompilerProvider.class": clazz = DecompilerProvider.class; break;
			case "DefaultFocusOwnerProvider.class": clazz = DefaultFocusOwnerProvider.class; break;
			case "DefaultGTreeFilterProvider.class": clazz = DefaultGTreeFilterProvider.class; break;
			//case "DefaultGraphDisplayComponentProvider.class": clazz = DefaultGraphDisplayComponentProvider.class; break;
			//case "DefaultGraphDisplayProvider.class": clazz = DefaultGraphDisplayProvider.class; break;
			case "DialogComponentProvider.class": clazz = DialogComponentProvider.class; break;
			case "DiffApplySettingsProvider.class": clazz = DiffApplySettingsProvider.class; break;
			case "DiffDetailsProvider.class": clazz = DiffDetailsProvider.class; break;
			case "DiffServiceProvider.class": clazz = DiffServiceProvider.class; break;
			case "DisplayStringProvider.class": clazz = DisplayStringProvider.class; break;
			//case "DualListingServiceProvider.class": clazz = DualListingServiceProvider.class; break;
			case "EditReferencesProvider.class": clazz = EditReferencesProvider.class; break;
			case "EditorProvider.class": clazz = EditorProvider.class; break;
			//case "ElfSectionProvider.class": clazz = ElfSectionProvider.class; break;
			case "EnumEditorProvider.class": clazz = EnumEditorProvider.class; break;
			case "EquateTableProvider.class": clazz = EquateTableProvider.class; break;
			case "ExperimentalLayoutProvider.class": clazz = ExperimentalLayoutProvider.class; break;
			//case "ExportAttributedGraphDisplayProvider.class": clazz = ExportAttributedGraphDisplayProvider.class; break;
			case "ExtensionTableProvider.class": clazz = ExtensionTableProvider.class; break;
			case "ExternalReferencesProvider.class": clazz = ExternalReferencesProvider.class; break;
			case "FGClipboardProvider.class": clazz = FGClipboardProvider.class; break;
			case "FGColorProvider.class": clazz = FGColorProvider.class; break;
			case "FGLayoutProvider.class": clazz = FGLayoutProvider.class; break;
			case "FGProvider.class": clazz = FGProvider.class; break;
			case "FGSatelliteUndockedProvider.class": clazz = FGSatelliteUndockedProvider.class; break;
			case "FGVertexTooltipProvider.class": clazz = FGVertexTooltipProvider.class; break;
			case "FcgProvider.class": clazz = FcgProvider.class; break;
			case "FcgTooltipProvider.class": clazz = FcgTooltipProvider.class; break;
			//case "FileBytesProvider.class": clazz = FileBytesProvider.class; break;
			//case "FileSystemBrowserComponentProvider.class": clazz = FileSystemBrowserComponentProvider.class; break;
			case "FocusOwnerProvider.class": clazz = FocusOwnerProvider.class; break;
			case "FunctionBitPatternsMainProvider.class": clazz = FunctionBitPatternsMainProvider.class; break;
			case "FunctionComparisonProvider.class": clazz = FunctionComparisonProvider.class; break;
			case "FunctionReachabilityProvider.class": clazz = FunctionReachabilityProvider.class; break;
			//case "FunctionTagProvider.class": clazz = FunctionTagProvider.class; break;
			case "FunctionWindowProvider.class": clazz = FunctionWindowProvider.class; break;
			case "GFileSystemProgramProvider.class": clazz = GFileSystemProgramProvider.class; break;
			case "GIconProvider.class": clazz = GIconProvider.class; break;
			case "GTreeFilterProvider.class": clazz = GTreeFilterProvider.class; break;
			case "GhidraScriptComponentProvider.class": clazz = GhidraScriptComponentProvider.class; break;
			case "GhidraScriptEditorComponentProvider.class": clazz = GhidraScriptEditorComponentProvider.class; break;
			case "GhidraScriptProvider.class": clazz = GhidraScriptProvider.class; break;
			//case "GraphDisplayProvider.class": clazz = GraphDisplayProvider.class; break;
			case "HighlightProvider.class": clazz = HighlightProvider.class; break;
			case "HoverProvider.class": clazz = HoverProvider.class; break;
			case "IconProvider.class": clazz = IconProvider.class; break;
			case "ImageDialogProvider.class": clazz = ImageDialogProvider.class; break;
			//case "ImmutableMemoryRangeByteProvider.class": clazz = ImmutableMemoryRangeByteProvider.class; break;
			//case "IndependentColorProvider.class": clazz = IndependentColorProvider.class; break;
			case "InputDialogComponentProvider.class": clazz = InputDialogComponentProvider.class; break;
			case "InputStreamByteProvider.class": clazz = InputStreamByteProvider.class; break;
			//case "InstructionInfoProvider.class": clazz = InstructionInfoProvider.class; break;
			case "IntegerEditorProvider.class": clazz = IntegerEditorProvider.class; break;
			case "IntegerRangeEditorProvider.class": clazz = IntegerRangeEditorProvider.class; break;
			case "InterpreterComponentProvider.class": clazz = InterpreterComponentProvider.class; break;
			case "JavaScriptProvider.class": clazz = JavaScriptProvider.class; break;
			case "JungLayoutProvider.class": clazz = JungLayoutProvider.class; break;
			case "KeyStorePasswordProvider.class": clazz = KeyStorePasswordProvider.class; break;
			case "LanguageProvider.class": clazz = LanguageProvider.class; break;
			case "LayoutProvider.class": clazz = LayoutProvider.class; break;
			case "ListingComparisonProvider.class": clazz = ListingComparisonProvider.class; break;
			case "ListingDiffHighlightProvider.class": clazz = ListingDiffHighlightProvider.class; break;
			case "ListingHighlightProvider.class": clazz = ListingHighlightProvider.class; break;
			case "ListingHoverProvider.class": clazz = ListingHoverProvider.class; break;
			case "ListingMergePanelProvider.class": clazz = ListingMergePanelProvider.class; break;
			case "LocationReferencesProvider.class": clazz = LocationReferencesProvider.class; break;
			case "LongEditorProvider.class": clazz = LongEditorProvider.class; break;
			case "LongRangeEditorProvider.class": clazz = LongRangeEditorProvider.class; break;
			case "MarginProvider.class": clazz = MarginProvider.class; break;
			case "MarkupItemFilterDialogComponentProvider.class": clazz = MarkupItemFilterDialogComponentProvider.class; break;
			case "MatchesFilterDialogComponentProvider.class": clazz = MatchesFilterDialogComponentProvider.class; break;
			//case "MemBufferByteProvider.class": clazz = MemBufferByteProvider.class; break;
			case "MemoryByteProvider.class": clazz = MemoryByteProvider.class; break;
			//case "MemoryMapProvider.class": clazz = MemoryMapProvider.class; break;
			case "MemoryMutableByteProvider.class": clazz = MemoryMutableByteProvider.class; break;
			//case "MergeManagerProvider.class": clazz = MergeManagerProvider.class; break;
			//case "MultiFunctionComparisonProvider.class": clazz = MultiFunctionComparisonProvider.class; break;
			//case "MultiProgramMemoryByteProvider.class": clazz = MultiProgramMemoryByteProvider.class; break;
			case "MutableByteProvider.class": clazz = MutableByteProvider.class; break;
			case "NamedSymbolProvider.class": clazz = NamedSymbolProvider.class; break;
			case "NullSectionProvider.class": clazz = NullSectionProvider.class; break;
			case "NumberColumnConstraintProvider.class": clazz = NumberColumnConstraintProvider.class; break;
			case "OverviewProvider.class": clazz = OverviewProvider.class; break;
			case "PatternEvalTableProvider.class": clazz = PatternEvalTableProvider.class; break;
			case "PatternMiningAnalyzerProvider.class": clazz = PatternMiningAnalyzerProvider.class; break;
			case "PopupActionProvider.class": clazz = PopupActionProvider.class; break;
			case "PopupKeyStorePasswordProvider.class": clazz = PopupKeyStorePasswordProvider.class; break;
			case "PrimaryDecompilerProvider.class": clazz = PrimaryDecompilerProvider.class; break;
			case "ProgramByteViewerComponentProvider.class": clazz = ProgramByteViewerComponentProvider.class; break;
			case "ProgramColumnConstraintProvider.class": clazz = ProgramColumnConstraintProvider.class; break;
			case "ProgramDropProvider.class": clazz = ProgramDropProvider.class; break;
			case "PythonScriptProvider.class": clazz = PythonScriptProvider.class; break;
			//case "RandomAccessByteProvider.class": clazz = RandomAccessByteProvider.class; break;
			case "RandomAccessMutableByteProvider.class": clazz = RandomAccessMutableByteProvider.class; break;
			//case "ReferenceProvider.class": clazz = ReferenceProvider.class; break;
			case "RegisterManagerProvider.class": clazz = RegisterManagerProvider.class; break;
			//case "RelocationProvider.class": clazz = RelocationProvider.class; break;
			//case "ScalarColumnConstraintProvider.class": clazz = ScalarColumnConstraintProvider.class; break;
			case "ScalarSearchProvider.class": clazz = ScalarSearchProvider.class; break;
			case "ServiceProvider.class": clazz = ServiceProvider.class; break;
			case "SetFormatDialogComponentProvider.class": clazz = SetFormatDialogComponentProvider.class; break;
			case "SimpleByteSequenceAnalyzerProvider.class": clazz = SimpleByteSequenceAnalyzerProvider.class; break;
			case "SleighLanguageProvider.class": clazz = SleighLanguageProvider.class; break;
			//case "SliceHighlightColorProvider.class": clazz = SliceHighlightColorProvider.class; break;
			case "StackEditorProvider.class": clazz = StackEditorProvider.class; break;
			case "StringColumnConstraintProvider.class": clazz = StringColumnConstraintProvider.class; break;
			case "StringTableProvider.class": clazz = StringTableProvider.class; break;
			case "StructureEditorProvider.class": clazz = StructureEditorProvider.class; break;
			//case "SymbolProvider.class": clazz = SymbolProvider.class; break;
			case "SymbolTreeProvider.class": clazz = SymbolTreeProvider.class; break;
			case "SynchronizedByteProvider.class": clazz = SynchronizedByteProvider.class; break;
			case "TOCItemProvider.class": clazz = TOCItemProvider.class; break;
			case "TableComponentProvider.class": clazz = TableComponentProvider.class; break;
			//case "TestFGLayoutProvider.class": clazz = TestFGLayoutProvider.class; break;
			//case "TestTreeComponentProvider.class": clazz = TestTreeComponentProvider.class; break;
			case "TextEditorComponentProvider.class": clazz = TextEditorComponentProvider.class; break;
			//case "TokenHighlightColorProvider.class": clazz = TokenHighlightColorProvider.class; break;
			//case "ToolBasedColorProvider.class": clazz = ToolBasedColorProvider.class; break;
			//case "TreeViewProvider.class": clazz = TreeViewProvider.class; break;
			case "UnionEditorProvider.class": clazz = UnionEditorProvider.class; break;
			case "UnsignedLongConstraintEditorProvider.class": clazz = UnsignedLongConstraintEditorProvider.class; break;
			case "UnsignedLongRangeEditorProvider.class": clazz = UnsignedLongRangeEditorProvider.class; break;
			case "VTDualListingHighlightProvider.class": clazz = VTDualListingHighlightProvider.class; break;
			case "VTFunctionAssociationProvider.class": clazz = VTFunctionAssociationProvider.class; break;
			case "VTImpliedMatchesTableProvider.class": clazz = VTImpliedMatchesTableProvider.class; break;
			case "VTMarkupItemsTableProvider.class": clazz = VTMarkupItemsTableProvider.class; break;
			case "VTMatchDestinationTableProvider.class": clazz = VTMatchDestinationTableProvider.class; break;
			case "VTMatchOneToManyTableProvider.class": clazz = VTMatchOneToManyTableProvider.class; break;
			case "VTMatchSourceTableProvider.class": clazz = VTMatchSourceTableProvider.class; break;
			case "VTMatchTableProvider.class": clazz = VTMatchTableProvider.class; break;
			case "VTRelatedMatchesTableProvider.class": clazz = VTRelatedMatchesTableProvider.class; break;
			case "VertexShapeProvider.class": clazz = VertexShapeProvider.class; break;
			case "VertexTooltipProvider.class": clazz = VertexTooltipProvider.class; break;
			case "ViewManagerComponentProvider.class": clazz = ViewManagerComponentProvider.class; break;
			case "ViewStringsColumnConstraintProvider.class": clazz = ViewStringsColumnConstraintProvider.class; break;
			case "ViewStringsProvider.class": clazz = ViewStringsProvider.class; break;
			case "VisualGraphComponentProvider.class": clazz = VisualGraphComponentProvider.class; break;
			default: System.out.println("No class mapping defined for "+providerName); return;
			}
			
			//Use tool.getWindowManager().getComponentProviders(JustAnotherProvider.class) 
			//If the provider name is a class name this should return a List of the specified provider type
			@SuppressWarnings("unchecked")
            List<ComponentProvider> providerList = aTool.getWindowManager().getComponentProviders(clazz);
			System.out.println("Found "+providerList.size()+" providers for class "+providerName);
			
			//Iterate over the set of providers returned and dump each in turn
			for(ComponentProvider cp : providerList) {
				System.out.println("Dumping hierarchy for component: "+cp.getName());
				recursivelyIterateComponentHierarchy(cp.getComponent(),0);
			}
			
			return;
		} 
		
		JComponent aComponent = aProvider.getComponent();
		if(aComponent == null) { //Exit if component is null
			System.out.println("JComponent returned by provider.getComponent() was null");
			return;
		}
		
		recursivelyIterateComponentHierarchy(aComponent,0);
	}

	/**
	 * Helper method for dumping Java Swing component hierarchy
	 * and associated listeners. 
	 * 
	 * This method uses recursion to dump the entire hierarchy. 
	 * 
	 * @param component
	 */
	public static void recursivelyIterateComponentHierarchy(JComponent component, int depth) {
		if(component == null) { 
			System.out.println("!!! JComponent was not initialized...skipping");
			return;
		}
		Component[] componentList = component.getComponents();
		
		//Iterate over each component in the list
		for(int i=0; i< componentList.length; i++) {
			Component theComponent = componentList[i];
			
			if(theComponent==null) {
				System.out.println("!!! Component not yet initialized...component skipping");
				return;
			}
			String cname = theComponent.getName();
			Class<?> cclass = theComponent.getClass();
			String indent = "|\t".repeat(depth);
			String indexStr = depth+"["+i+"]";
			System.out.println(indent+indexStr+cclass+", "+"name["+cname+"]" );
			
			printAllComponentListeners(theComponent,depth+1);
			
			try {
				//This will not always work... not all Components are JComponents 
				JComponent theJComponent = (JComponent)theComponent;
				//Recursive call
				recursivelyIterateComponentHierarchy(theJComponent,depth+1);
			} catch(ClassCastException e) {
				//TODO: probably a relatively rare exception, so maybe ignore these components
				System.out.println(indent+indexStr+cclass+" !! Class cast exception (JComponent) for "+theComponent.toString());
			} catch(NullPointerException e) {
				//Should not be able to get to this point if the component is null
				System.out.println(indent+indexStr+cclass+" !! JComponent was not initialized");
			}
		}
		
		return; //When there are no more components, return
		
	}

	/**
	 * Fetches and prints all listeners for the provided component. 
	 * 
	 * @param component the component for which we are enumerating listeners
	 * @param depth the relative depth of the component from the starting point in the component hierarchy 
	 */
	public static void printAllComponentListeners(Component component, int depth) {
		ComponentListener[] l1 = component.getComponentListeners();
		printEventListenerDetails(l1,depth);
		
		FocusListener[] l2 = component.getFocusListeners();
		printEventListenerDetails(l2,depth);
		
		HierarchyBoundsListener[] l3 = component.getHierarchyBoundsListeners();
		printEventListenerDetails(l3,depth);
		
		HierarchyListener[] l4 = component.getHierarchyListeners();
		printEventListenerDetails(l4,depth);
		
		InputMethodListener[] l5 = component.getInputMethodListeners();
		printEventListenerDetails(l5,depth);
		
		KeyListener[] l6 = component.getKeyListeners();
		printEventListenerDetails(l6,depth);
		
		MouseListener[] l7 = component.getMouseListeners();
		printEventListenerDetails(l7,depth);
		
		MouseMotionListener[] l8 = component.getMouseMotionListeners();
		printEventListenerDetails(l8,depth);
		
		MouseWheelListener[] l9 = component.getMouseWheelListeners();
		printEventListenerDetails(l9,depth);
		
		
		PropertyChangeListener[] l10 = component.getPropertyChangeListeners();
		printEventListenerDetails(l10,depth);
		
	}
	
	/**
	 * Helper method for printing an event listener with nice formatting
	 * @param listeners the event listeners to print
	 * @param depth the relative depth of the component associated with the listeners
	 */
	public static void printEventListenerDetails(EventListener[] listeners, int depth) {
		for(EventListener l : listeners) {
			String indent = "|\t".repeat(depth);
			System.out.println(indent+"EventListener "+l.toString());
			
		}
	}
	
	
	/**
	 * A simple provider which takes a text string of the provider name or provider class name
	 * 
	 * TODO: Add a simple text area for entering in component names...?  
	 * TODO: add button for injecting listeners 
	 * TODO: add a global hotkey to trigger dumping active component providers
	 * 
	 * @author vagrant
	 */
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction dumpComponentHierarchy;
		//private DockingAction dump
		private JTextArea textArea;
		private PluginTool theTool;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			
			//Obtain a reference to the PluginTool that this component is a provider for
			theTool = plugin.getTool(); 
			buildPanel();
			createActions();
			
			//KeyBindingUtils.registerAction(component, keyStroke, action, focusCondition);
			//KeyBindingData kb = new KeyBindingData(KeyEvent.VK_P,InputEvent.META_DOWN_MASK);
			
		}

		// Customize GUI
		private void buildPanel() {
			panel = new JPanel(new BorderLayout());
			textArea = new JTextArea(5, 25);
			textArea.setEditable(true);
			textArea.setText("Decompiler");
			panel.add(new JScrollPane(textArea));
			setVisible(true);
		}

		// TODO: Customize actions
		private void createActions() {
			dumpComponentHierarchy = new DockingAction("Dump Component Hierarchy", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					//TODO: Silently dump this to stdout
					//Msg.showInfo(getClass(), panel, "Dump Component Hierarchy", "Component hierarchy is being printed to stdout");
					exploreComponentHierarchy(theTool, textArea.getText());
				}
			};
			
			//Set a global keybinding to dump the component hierarchy in a particular UI context/focus
			KeyBindingData kb = new KeyBindingData(KeyEvent.VK_I,InputEvent.ALT_DOWN_MASK | InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
			dumpComponentHierarchy.setKeyBindingData(kb);
			dumpComponentHierarchy.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			dumpComponentHierarchy.setEnabled(true);
			dumpComponentHierarchy.markHelpUnnecessary();
			//dumpComponentHierarchy.
			//dockingTool.addLocalAction(this, dumpComponentHierarchy);
			dockingTool.addAction(dumpComponentHierarchy);
			
			
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
